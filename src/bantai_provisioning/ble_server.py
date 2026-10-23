
#!/usr/bin/env python3

"""Initial BANTAI BLE GATT identity server."""

import argparse
import asyncio
import json
from pathlib import Path

from dbus_next import BusType, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, method, dbus_property

from bantai_provisioning.device_identity import build_identity


ROOT = "/com/bantai/gatt"
SERVICE_PATH = ROOT + "/service0"
CHAR_PATH = SERVICE_PATH + "/char0"
ADV_PATH = "/com/bantai/advertisement"

SERVICE_UUID = "8b7e1000-6d7a-4e9a-9c4e-123456789001"
IDENTITY_UUID = "8b7e1003-6d7a-4e9a-9c4e-123456789001"


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
            CHAR_PATH: {
                "org.bluez.GattCharacteristic1": {
                    "UUID": v("s", IDENTITY_UUID),
                    "Service": v("o", SERVICE_PATH),
                    "Flags": v("as", ["read"]),
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

        return payload


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


async def main(adapter_path: str, state_dir: Path):
    identity = build_identity(state_dir)

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    # Export the GATT application and its objects.
    bus.export(ROOT, Application())
    bus.export(SERVICE_PATH, GattService())
    bus.export(CHAR_PATH, IdentityCharacteristic(identity))

    # Export the BLE advertisement.
    bus.export(ADV_PATH, Advertisement())

    introspection = await bus.introspect("org.bluez", adapter_path)
    proxy = bus.get_proxy_object(
        "org.bluez", adapter_path, introspection
    )

    gatt = proxy.get_interface("org.bluez.GattManager1")
    advertising = proxy.get_interface("org.bluez.LEAdvertisingManager1")

    registered_gatt = False
    registered_advertisement = False

    try:
        await gatt.call_register_application(ROOT, {})
        registered_gatt = True

        await advertising.call_register_advertisement(ADV_PATH, {})
        registered_advertisement = True

        print("[BANTAI] BLE identity server is running")
        print(f"[BANTAI] Device: {identity['device_id']}")
        print("[BANTAI] Advertising name: BANTAI-Pi")
        print(f"[BANTAI] Service UUID: {SERVICE_UUID}")
        print(f"[BANTAI] Identity UUID: {IDENTITY_UUID}")
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
    args = parser.parse_args()

    asyncio.run(main(args.adapter, args.state_dir))
