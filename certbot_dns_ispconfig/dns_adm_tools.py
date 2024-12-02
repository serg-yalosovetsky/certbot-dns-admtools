"""DNS Authenticator for ISPConfig."""
import json
import logging
import time

import httpx
import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for adm.tools

    This Authenticator uses the adm.tools Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using adm.tools for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="adm.tools credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the adm.tools REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "adm.tools credentials INI file",
            {
                "auth_token": "Auth token for adm.tools Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_ispconfig_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_ispconfig_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_ispconfig_client(self):
        return _ISPConfigClient(
            self.credentials.conf("auth_token"),
        )


class _ISPConfigClient(object):
    """
    Encapsulates all communication with the adm.tools Remote REST API.
    """

    def __init__(self, auth_token):
        logger.debug("creating ispconfigclient")
        self.auth_token = auth_token
        self.domain_list_url = "https://adm.tools/action/dns/list/"
        self.dns_list_url = "https://adm.tools/action/dns/records_list/"
        self.dns_add_url = "https://adm.tools/action/dns/record_add/"
        self.dns_delete_url = "https://adm.tools/action/dns/record_delete/"
        self.dns_update_url = "https://adm.tools/action/dns/record_update/"
        self.domain_ids = {}
        self.session = requests.Session()
        self.session_id = None


    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        if not self.domain_ids or domain not in self.domain_ids:
            self._get_domains(domain=domain)
        record_id = self._get_dns_record_id(domain, record_name, 'TXT')
        if record_id is not None:
            self._update_dns_record(domain, record_id, record_content, record_ttl)
        else:
            self._add_dns_record(domain, 'TXT', record_name, record_content, record_ttl)


    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        if not self.domain_ids or domain not in self.domain_ids:
            self._get_domains(domain=domain)
        record_id = self._get_dns_record_id(domain, record_name, 'TXT')
        if record_id is None:
            raise errors.PluginError("Record not found")
        self._remove_dns_record(domain, record_id)


    def _get_domains(self, domain: str = ''):
        post_data = {
            'by': 'asc',
            'domains_search_request': domain or '',
            'p': 1,
            'sort': 'name',
            'tag_free': 0,
            'tag_id': 0,
        }

        auth_headers = {
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = self.session.post(self.domain_list_url, headers=auth_headers, data=post_data)

        response_json = response.json()
        if response.status_code == 200 and response_json['result'] == 'true':
            domains_list  = response_json['response']['list']
            if len(domains_list.keys()) == 1:
                self.domain_ids[domains_list.keys()[0]] = int(domains_list.keys()[0]['domain_id'])
                return True
            elif domain:
                for domain_name, domain_data in domains_list.items():
                    if domain_name == domain:
                        self.domain_ids[domain_name] = int(domain_data['domain_id'])
                        return True
                if not self.domain_ids[domain]:
                    raise errors.PluginError("Domain not found")
            else:
                for domain_name, domain_data in domains_list.items():
                    self.domain_ids[domain_name] = int(domain_data['domain_id'])
                return True
        else:
            raise errors.PluginError("Failed to get domains")
        if not self.domain_ids:
            raise errors.PluginError("Domain ID not found")
        
        
    def _get_dns_records(self, domain: str, record_type: str = ''):
        if not self.domain_ids or domain not in self.domain_ids:
            raise errors.PluginError("Domain ID not found")
        if not isinstance(record_type, str):
            raise errors.PluginError("Record type must be a string")
        
        post_data = {
            'domain_id': self.domain_ids[domain],
        }

        auth_headers = {
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = self.session.post(self.dns_list_url, headers=auth_headers, data=post_data)

        response_json = response.json()
        if response.status_code == 200 and response_json['result'] == 'true':
            return [record for record in response_json['response']['list'] if record_type.lower() in record['type'].lower()]
        else:
            raise errors.PluginError("Failed to get DNS records")
        
    def _get_dns_record_id(self, domain: str, record_name: str, record_type: str):
        dns_records = self._get_dns_records(domain, record_type)
        for record in dns_records:
            if record['record'] == record_name:
                return record['id']
        return None
        
    def _add_dns_record(self, domain: str, record_type: str, record_name: str, record_content: str, record_ttl: int, priority: int = 0):
        post_data = {
            'domain_id': self.domain_ids[domain],
            'type': record_type,
            'data': record_content,
            'priority': priority,
            'record': record_name,
        }

        auth_headers = {
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = self.session.post(self.dns_add_url, headers=auth_headers, data=post_data)

        response_json = response.json()
        if response.status_code == 200 and response_json['result'] == 'true':
            return True
        else:
            raise errors.PluginError("Failed to add DNS record")
        

    def _update_dns_record(self, domain: str, record_id: int, record_content: str, priority: int = 0):
        post_data = {
            'data': record_content,
            'subdomain_id': record_id,
            'priority': priority,
        }

        auth_headers = {
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = self.session.post(self.dns_update_url, headers=auth_headers, data=post_data)

        response_json = response.json()
        if response.status_code == 200 and response_json['result'] == 'true':
            return True
        else:
            raise errors.PluginError("Failed to update DNS record")
        

    def _remove_dns_record(self, domain: str, record_id: int):
        post_data = {
            'subdomain_id': record_id,
        }

        auth_headers = {
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = self.session.post(self.dns_delete_url, headers=auth_headers, data=post_data)

        response_json = response.json()
        if response.status_code == 200 and response_json['result'] == 'true':
            return True
        else:
            raise errors.PluginError("Failed to remove DNS record")
        

    def get_existing_txt(self, domain: str, record_name: str, record_content: str):
        """
        Get existing TXT records from the RRset for the record name.

        If an error occurs while requesting the record set, it is suppressed
        and None is returned.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: TXT record value or None
        :rtype: `string` or `None`

        """
        if not self.domain_ids or domain not in self.domain_ids:
            self._get_domains(domain=domain)
        dns_records = self._get_dns_records(domain, 'TXT')
        for entry in dns_records:
            if (
                entry["name"] == record_name
                and entry["type"] == "TXT"
                and entry["data"] == record_content
            ):
                return entry
        return None
