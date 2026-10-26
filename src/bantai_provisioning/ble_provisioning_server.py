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

DEFAULT_MTU = 23
MAX_MESSAGE = 4096


def v(signature, value):
    return Variant(signature, value)


def opt(options, key, default):
    item = options.get(key)
    return item.value if item is not None else default


class Application(ServiceInterface):
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
        self._payload = json.dumps(
            identity, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

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
        offset = opt(options, "offset", 0)
        return self._payload[offset:]


class ProvisioningCharacteristic(ServiceInterface):
    """
    Framing (both directions): message = 2-byte big-endian length + body,
    split across as many GATT packets as needed. Responses are sent as
    notifications because BlueZ discards WriteValue return values.
    """

    def __init__(self, device_id: str, identity_key, setup_token: str, hotspot_config: HotspotConfig):
        super().__init__("org.bluez.GattCharacteristic1")
        self.device_id = device_id
        self.identity_key = identity_key
        self.setup_token = setup_token
        self.hotspot_config = hotspot_config
        self._make_session = lambda: ProvisioningSession(
            ProvisioningHandshake(
                device_id=self.device_id,
                identity_key=self.identity_key,
                setup_token=self.setup_token,
            ),
            self.hotspot_config,
        )
        self.session = self._make_session()
        self._notifying = False
        self._value = b""
        self._rx = bytearray()
        self._mtu = DEFAULT_MTU
        self._tx_lock = asyncio.Lock()

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return PROVISION_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE_PATH

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return ["write", "notify"]

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return self._value

    @dbus_property(access=PropertyAccess.READ)
    def Notifying(self) -> "b":
        return self._notifying

    @method()
    def StartNotify(self):
        self._notifying = True
        self._rx.clear()
        # Create a fresh session for each new client connection
        try:
            if getattr(self.session, "is_closed", False) or getattr(self.session, "_closed", False):
                print("[BANTAI] Previous session closed, starting new session", flush=True)
                self.session = self._make_session()
        except Exception:
            pass
        print("[BANTAI] Client subscribed to provisioning notifications", flush=True)

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        self._mtu = opt(options, "mtu", self._mtu)
        chunk = bytes(value)
        print(f"[BANTAI] GATT WriteValue: {len(chunk)} bytes, mtu={self._mtu}", flush=True)
        try:
            print(f"[BANTAI] Write chunk preview: {chunk[:200]!r}", flush=True)
        except Exception:
            pass
        self._rx.extend(chunk)

        if len(self._rx) < 2:
            return
        expected = int.from_bytes(self._rx[:2], "big")
        if expected > MAX_MESSAGE:
            print(f"[BANTAI] Message too large ({expected} > {MAX_MESSAGE}), clearing buffer", flush=True)
            self._rx.clear()
            return
        if len(self._rx) < 2 + expected:
            print(f"[BANTAI] Waiting for more chunks: have {len(self._rx)}, need {2+expected}", flush=True)
            return  # wait for more chunks

        message = bytes(self._rx[2:2 + expected])
        self._rx.clear()
        print(f"[BANTAI] Received complete message ({len(message)} bytes)", flush=True)
        asyncio.get_running_loop().create_task(self._handle(message))

    async def _handle(self, message: bytes):
        try:
            print(f"[BANTAI] Processing message: {message[:300]!r}", flush=True)
            response = await asyncio.to_thread(self.session.process_message, message)
            print(f"[BANTAI] Session response: {len(response) if response else 0} bytes", flush=True)
            if response:
                try:
                    print(f"[BANTAI] Response preview: {bytes(response)[:300]!r}", flush=True)
                except Exception:
                    pass
        except Exception as e:
            print(f"[BANTAI] process_message error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            response = json.dumps({"type": "error", "error": "internal"}).encode()
        if response:
            await self._send(bytes(response))

    async def _send(self, data: bytes):
        framed = len(data).to_bytes(2, "big") + data
        chunk = max(20, self._mtu - 3)
        async with self._tx_lock:
            for i in range(0, len(framed), chunk):
                self._value = framed[i:i + chunk]
                self.emit_properties_changed({"Value": self._value})
                await asyncio.sleep(0.03)  # let BlueZ flush each packet


class Advertisement(ServiceInterface):
    def __init__(self, local_name: str):
        super().__init__("org.bluez.LEAdvertisement1")
        self._name = local_name

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [SERVICE_UUID]

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return self._name

    @method()
    def Release(self):
        print("[BANTAI] Advertisement released")


async def main(adapter_path: str, state_dir: Path, setup_token: str):
    identity = build_identity(state_dir)
    identity_key = load_or_create_key(state_dir)
    hotspot_config = HotspotConfig(state_dir / "hotspot")

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    bus.export(ROOT, Application())
    bus.export(SERVICE_PATH, GattService())
    bus.export(IDENTITY_CHAR_PATH, IdentityCharacteristic(identity))
    bus.export(PROVISION_CHAR_PATH, ProvisioningCharacteristic(
        device_id=identity["device_id"],
        identity_key=identity_key,
        setup_token=setup_token,
        hotspot_config=hotspot_config,
    ))
    bus.export(ADV_PATH, Advertisement(identity["device_id"]))

    introspection = await bus.introspect("org.bluez", adapter_path)
    proxy = bus.get_proxy_object("org.bluez", adapter_path, introspection)
    gatt = proxy.get_interface("org.bluez.GattManager1")
    advertising = proxy.get_interface("org.bluez.LEAdvertisingManager1")

    registered_gatt = registered_adv = False
    try:
        await gatt.call_register_application(ROOT, {})
        registered_gatt = True
        await advertising.call_register_advertisement(ADV_PATH, {})
        registered_adv = True

        print("[BANTAI] BLE provisioning server is running")
        print(f"[BANTAI] Device: {identity['device_id']}")
        print(f"[BANTAI] Service UUID: {SERVICE_UUID}")
        await asyncio.Future()
    finally:
        if registered_adv:
            await advertising.call_unregister_advertisement(ADV_PATH)
        if registered_gatt:
            await gatt.call_unregister_application(ROOT)
        bus.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", default="/org/bluez/hci0")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/state/bantai-provisioning",
    )
    parser.add_argument("--setup-token")
    args = parser.parse_args()

    token = args.setup_token or secrets.token_urlsafe(32)
    asyncio.run(main(args.adapter, args.state_dir, token))