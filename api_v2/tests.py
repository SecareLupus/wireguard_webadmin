import json
from unittest.mock import patch

from django.test import TestCase

from api_v2.models import ApiKey
from dns.models import DNSSettings, StaticHost
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance


class ApiV2ManagePeerAllocationCidrTests(TestCase):
    def setUp(self):
        self.instance = WireGuardInstance.objects.create(
            name="wg-test",
            instance_id=99,
            private_key="server-private-key",
            public_key="server-public-key",
            hostname="localhost",
            listen_port=51999,
            address="10.100.0.1",
            netmask=24,
        )
        self.api_key = ApiKey.objects.create(name="test-key", enabled=True)
        self.url = "/api/v2/manage_peer/"

    def _create_peer_with_main_ip(self, ip_address: str, idx: int = 0):
        peer = Peer.objects.create(
            name=f"peer-{idx}",
            public_key=f"public-key-{idx}",
            pre_shared_key=f"psk-{idx}",
            private_key=f"private-key-{idx}",
            persistent_keepalive=25,
            wireguard_instance=self.instance,
        )
        PeerAllowedIP.objects.create(
            config_file="server",
            peer=peer,
            allowed_ip=ip_address,
            priority=0,
            netmask=32,
        )
        return peer

    def _fake_func_create_new_peer(self, wireguard_instance, overrides=None):
        overrides = overrides or {}
        allowed_ip = overrides.get("allowed_ip")
        if not allowed_ip:
            allowed_ip = wireguard_instance.next_available_ip_address
        if not allowed_ip:
            return None, "Error creating peer|No available IP address found for peer creation."

        peer = Peer.objects.create(
            name=overrides.get("name", ""),
            public_key=overrides.get("public_key", "new-public-key"),
            pre_shared_key=overrides.get("pre_shared_key", "new-pre-shared-key"),
            private_key=overrides.get("private_key", "new-private-key"),
            persistent_keepalive=overrides.get("persistent_keepalive", 25),
            wireguard_instance=wireguard_instance,
            routing_template=overrides.get("default_routing_template"),
        )
        PeerAllowedIP.objects.create(
            config_file="server",
            peer=peer,
            allowed_ip=allowed_ip,
            priority=0,
            netmask=int(overrides.get("allowed_ip_netmask", 32) or 32),
        )
        return peer, "Peer created successfully."

    @patch("api_v2.views_api.func_create_new_peer")
    def test_manage_peer_create_allocation_cidr_allocates_next_free_ip(self, mock_create):
        mock_create.side_effect = self._fake_func_create_new_peer
        self._create_peer_with_main_ip("10.100.0.17", idx=1)

        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg99",
                "name": "allocated-peer",
                "allocation_cidr": "10.100.0.16/28",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        created_peer = Peer.objects.get(uuid=body["peer_uuid"])
        main_ip = PeerAllowedIP.objects.get(peer=created_peer, config_file="server", priority=0)
        self.assertEqual(main_ip.allowed_ip, "10.100.0.18")

    @patch("api_v2.views_api.func_create_new_peer")
    def test_manage_peer_create_rejects_allocation_cidr_outside_instance_network(self, mock_create):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg99",
                "name": "allocated-peer",
                "allocation_cidr": "10.101.0.0/24",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("allocation_cidr must be within", response.json()["error_message"])
        mock_create.assert_not_called()

    @patch("api_v2.views_api.func_create_new_peer")
    def test_manage_peer_create_rejects_exhausted_allocation_cidr(self, mock_create):
        self._create_peer_with_main_ip("10.100.0.9", idx=1)
        self._create_peer_with_main_ip("10.100.0.10", idx=2)

        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg99",
                "name": "allocated-peer",
                "allocation_cidr": "10.100.0.8/30",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("No available IP address found in allocation_cidr", response.json()["error_message"])
        mock_create.assert_not_called()

    @patch("api_v2.views_api.func_create_new_peer")
    def test_manage_peer_create_rejects_allowed_ip_and_allocation_cidr_together(self, mock_create):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg99",
                "name": "allocated-peer",
                "allowed_ip": "10.100.0.20",
                "allocation_cidr": "10.100.0.16/28",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("either allowed_ip or allocation_cidr", response.json()["error_message"])
        mock_create.assert_not_called()


class ApiV2ManageDnsRecordTests(TestCase):
    def setUp(self):
        self.api_key = ApiKey.objects.create(name="dns-test-key", enabled=True)
        self.url = "/api/v2/manage_dns_record/"

    @staticmethod
    def _fake_export_dns_configuration():
        dns_settings, _ = DNSSettings.objects.get_or_create(name="dns_settings")
        dns_settings.pending_changes = False
        dns_settings.save(update_fields=["pending_changes", "updated"])

    @patch("api_v2.views_api.export_dns_configuration")
    def test_create_dns_record_with_skip_apply_sets_pending_changes(self, mock_export):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "hostname": "App.Example.com",
                "ip_address": "10.20.30.40",
                "skip_apply": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["hostname"], "app.example.com")
        self.assertEqual(body["ip_address"], "10.20.30.40")
        mock_export.assert_not_called()

        record = StaticHost.objects.get(hostname="app.example.com")
        self.assertEqual(str(record.ip_address), "10.20.30.40")
        dns_settings = DNSSettings.objects.get(name="dns_settings")
        self.assertTrue(dns_settings.pending_changes)

    @patch("api_v2.views_api.export_dns_configuration")
    def test_create_dns_record_applies_when_skip_apply_false(self, mock_export):
        mock_export.side_effect = self._fake_export_dns_configuration
        DNSSettings.objects.create(name="dns_settings", pending_changes=True)

        response = self.client.post(
            self.url,
            data=json.dumps({
                "hostname": "api.example.com",
                "ip_address": "10.20.30.41",
                "skip_apply": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 201)
        mock_export.assert_called_once()
        dns_settings = DNSSettings.objects.get(name="dns_settings")
        self.assertFalse(dns_settings.pending_changes)

    @patch("api_v2.views_api.export_dns_configuration")
    def test_post_upserts_existing_dns_record(self, mock_export):
        mock_export.side_effect = self._fake_export_dns_configuration
        StaticHost.objects.create(hostname="app.example.com", ip_address="10.20.30.40")

        response = self.client.post(
            self.url,
            data=json.dumps({
                "hostname": "app.example.com",
                "ip_address": "10.20.30.99",
                "skip_apply": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "DNS record updated successfully.")
        record = StaticHost.objects.get(hostname="app.example.com")
        self.assertEqual(str(record.ip_address), "10.20.30.99")
        self.assertEqual(StaticHost.objects.filter(hostname="app.example.com").count(), 1)
        mock_export.assert_called_once()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_put_updates_dns_record_by_hostname(self, mock_export):
        mock_export.side_effect = self._fake_export_dns_configuration
        StaticHost.objects.create(hostname="vpn.example.com", ip_address="10.1.1.10")

        response = self.client.put(
            self.url,
            data=json.dumps({
                "hostname": "vpn.example.com",
                "ip_address": "10.1.1.20",
                "skip_apply": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "DNS record updated successfully.")
        record = StaticHost.objects.get(hostname="vpn.example.com")
        self.assertEqual(str(record.ip_address), "10.1.1.20")
        mock_export.assert_called_once()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_put_returns_404_when_record_missing(self, mock_export):
        response = self.client.put(
            self.url,
            data=json.dumps({
                "hostname": "missing.example.com",
                "ip_address": "10.1.1.20",
                "skip_apply": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("not found", response.json()["error_message"])
        mock_export.assert_not_called()
