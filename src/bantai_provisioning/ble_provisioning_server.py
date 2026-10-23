#!/usr/bin/env python3

"""BLE GATT provisioning server for BANTAI Pi setup."""

import argparse
import asyncio
import json
import secrets
from pathlib import Path

from dbus_next import BusType, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, method, dbus_property

from bantai_provisioning.device_identity import build_identity, load_or_create_key
from bantai_provisioning.provisioning_session import HotspotConfig, ProvisioningSession
from bantai_provisioning.security import ProvisioningHandshake

ROOT = "/com/bantai/gatt"
SERVICE_PATH = ROOT + "/service0"
IDENTITY_CHAR_PATH = SERVICE_PATH + "/char0"
PROVISION_CHAR_PATH = SERVICE_PATH + "/char1"
ADV_PATH = "/com/bantai/advertisement"

SERVICE_UUID = "8b7e1000-6d7a-4e9a-9c4e-123456789001"
IDENTITY_UUID = "8b7e1003-6d7a-4e9a-9c4e-123456789001"
PROVISION_UUID = "8b7e1004-6d7a-4e9a-9c4e-123456789001"


def v(signature, value):
    return Variant(signature, value)


class Application(ServiceInterface):
    """GATT application ObjectManager."""

    def __init__(self):
        super().__init__("org.freedesktop.DBus.ObjectManager")

    @method()
    def GetManagedObjects(self) -> "a{oa{sa{sv}}}":
        return {
            SERVICE_PATH: {
                "org.bluez.GattService1": {
                    "UUID": v("s", SERVICE_UUID),
                    "Primary": v("b", True),
                    "Includes": v("ao", []),
                }
            },
            IDENTITY_CHAR_PATH: {
                "org.bluez.GattCharacteristic1": {
                    "UUID": v("s", IDENTITY_UUID),
                    "Service": v("o", SERVICE_PATH),
                    "Flags": v("as", ["read"]),
                }
            },
            PROVISION_CHAR_PATH: {
                "org.bluez.GattCharacteristic1": {
                    "UUID": v("s", PROVISION_UUID),
                    "Service": v("o", SERVICE_PATH),
                    "Flags": v("as", ["write", "notify"]),
                }
            },
        }


class GattService(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.GattService1")

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return SERVICE_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":
        return True

    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> "ao":
        return []


class IdentityCharacteristic(ServiceInterface):
    def __init__(self, identity):
        super().__init__("org.bluez.GattCharacteristic1")
        self.identity = identity

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return IDENTITY_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE_PATH

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return ["read"]

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        payload = json.dumps(
            self.identity,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return [b for b in payload]


class ProvisioningCharacteristic(ServiceInterface):
    def __init__(self, session: ProvisioningSession):
        super().__init__("org.bluez.GattCharacteristic1")
        self.session = session
        self._subscribed = False
        self._pending_notifications = []

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return PROVISION_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE_PATH

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return ["write", "notify"]

    @method()
    def StartNotify(self):
        self._subscribed = True
        print("[BANTAI] Client subscribed to provisioning notifications")

    @method()
    def StopNotify(self):
        self._subscribed = False
        print("[BANTAI] Client unsubscribed from provisioning notifications")

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}") -> "ay":
        """Handle incoming provisioning messages."""
        try:
            message = bytes(value)
            response = self.session.process_message(message)

            if response:
                return [b for b in response]

            return []

        except Exception as e:
            error_response = json.dumps({
                "type": "error",
                "error": str(e),
            }).encode("utf-8")
            return [b for b in error_response]


class Advertisement(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.LEAdvertisement1")

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [SERVICE_UUID]

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return "BANTAI-Pi"

    @method()
    def Release(self):
        print("[BANTAI] Advertisement released")


async def main(adapter_path: str, state_dir: Path, setup_token: str):
    identity = build_identity(state_dir)
    identity_key = load_or_create_key(state_dir)

    handshake = ProvisioningHandshake(
        device_id=identity["device_id"],
        identity_key=identity_key,
        setup_token=setup_token,
    )

    hotspot_config = HotspotConfig(state_dir / "hotspot")
    session = ProvisioningSession(handshake, hotspot_config)

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    bus.export(ROOT, Application())
    bus.export(SERVICE_PATH, GattService())
    bus.export(IDENTITY_CHAR_PATH, IdentityCharacteristic(identity))
    bus.export(PROVISION_CHAR_PATH, ProvisioningCharacteristic(session))
    bus.export(ADV_PATH, Advertisement())

    introspection = await bus.introspect("org.bluez", adapter_path)
    proxy = bus.get_proxy_object("org.bluez", adapter_path, introspection)

    gatt = proxy.get_interface("org.bluez.GattManager1")
    advertising = proxy.get_interface("org.bluez.LEAdvertisingManager1")

    registered_gatt = False
    registered_advertisement = False

    try:
        await gatt.call_register_application(ROOT, {})
        registered_gatt = True

        await advertising.call_register_advertisement(ADV_PATH, {})
        registered_advertisement = True

        print("[BANTAI] BLE provisioning server is running")
        print(f"[BANTAI] Device: {identity['device_id']}")
        print(f"[BANTAI] Setup token: {setup_token}")
        print("[BANTAI] Advertising name: BANTAI-Pi")
        print(f"[BANTAI] Service UUID: {SERVICE_UUID}")
        print(f"[BANTAI] Identity UUID: {IDENTITY_UUID}")
        print(f"[BANTAI] Provision UUID: {PROVISION_UUID}")
        print("[BANTAI] Press Ctrl+C to stop")

        await asyncio.Future()

    finally:
        if registered_advertisement:
            await advertising.call_unregister_advertisement(ADV_PATH)

        if registered_gatt:
            await gatt.call_unregister_application(ROOT)

        bus.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--adapter",
        default="/org/bluez/hci0",
        help="BlueZ adapter object path",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/state/bantai-provisioning",
    )
    parser.add_argument(
        "--setup-token",
        help="One-time setup token (generated if not provided)",
    )
    args = parser.parse_args()

    token = args.setup_token or secrets.token_urlsafe(32)
    asyncio.run(main(args.adapter, args.state_dir, token))
