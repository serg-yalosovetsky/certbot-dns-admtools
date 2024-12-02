"""Tests for certbot_dns_admtools.dns_admtools."""

import unittest

import mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_USER = "remoteuser"
FAKE_AUTH_TOKEN = "auth_token"


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_admtools.dns_admtools import Authenticator

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "admtools_auth_token": FAKE_AUTH_TOKEN,
            },
            path,
        )

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(
            admtools_credentials=path, admtools_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "admtools")

        self.mock_client = mock.MagicMock()
        # _get_admtools_client | pylint: disable=protected-access
        self.auth._get_admtools_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)


class AdmToolsClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42

    def setUp(self):
        from certbot_dns_admtools.dns_admtools import _AdmToolsClient

        self.adapter = requests_mock.Adapter()

        self.client = _AdmToolsClient(FAKE_AUTH_TOKEN)
        self.client.session.mount("mock", self.adapter)

    def _register_response(
        self, ep_id, response=None, message=None, additional_matcher=None, **kwargs
    ):
        resp = {"code": "ok", "message": message, "response": response}
        if message is not None:
            resp["code"] = "remote_failure"

        def add_matcher(request):
            data = json.loads(request.text)
            add_result = True
            if additional_matcher is not None:
                add_result = additional_matcher(request)

            return (
                (
                    ("auth_token" in data and data["auth_token"] == FAKE_AUTH_TOKEN)
                )
                or data["session_id"] == "FAKE_SESSION"
            ) and add_result

        self.adapter.register_uri(
            requests_mock.ANY,
            "mock://endpoint?{0}".format(ep_id),
            text=json.dumps(resp),
            additional_matcher=add_matcher,
            **kwargs
        )

    def test_add_txt_record(self):
        self._register_response("login", response="FAKE_SESSION")
        self._register_response("dns_zone_get_id", response=23)
        self._register_response("dns_txt_add", response=99)
        self._register_response(
            "dns_zone_get", response={"zone_id": 102, "server_id": 1}
        )
        self._register_response("dns_rr_get_all_by_zone", response=[])
        self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl
        )

    def test_add_txt_record_fail_to_find_domain(self):
        self._register_response("login", response="FAKE_SESSION")
        self._register_response("dns_zone_get_id", message="Not Found")
        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_add_txt_record_fail_to_authenticate(self):
        self._register_response("login", message="FAILED")
        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_del_txt_record(self):
        self._register_response("login", response="FAKE_SESSION")
        self._register_response("dns_zone_get_id", response=23)
        self._register_response("dns_rr_get_all_by_zone", response=[])
        self._register_response("dns_txt_delete", response="")
        self.client.del_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl
        )

    def test_del_txt_record_fail_to_find_domain(self):
        self._register_response("login", response="FAKE_SESSION")
        self._register_response("dns_zone_get_id", message="Not Found")
        with self.assertRaises(errors.PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_del_txt_record_fail_to_authenticate(self):
        self._register_response("login", message="FAILED")
        with self.assertRaises(errors.PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
