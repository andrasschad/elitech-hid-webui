#!/usr/bin/env python3

import json
import logging
import os
import select
import secrets
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser

from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse


APP_VERSION = "v21-tab-session-recovery"

HOST = "127.0.0.1"
PORT = 8765

ELITECH_VENDOR_ID = "246C"
ELITECH_PRODUCT_ID = "9001"

HID_LOCK = threading.Lock()
APP_TOKEN = secrets.token_urlsafe(32)

DEBUG_LOG_PATH = Path.cwd() / "elitech-debug.log"

LOGGER = logging.getLogger("elitech_rc5")
LOGGER.setLevel(logging.DEBUG)

if not LOGGER.handlers:
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler = RotatingFileHandler(
        DEBUG_LOG_PATH,
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console_handler)


def frame_hex(data: bytes, frame_length=None) -> str:
    if frame_length is None:
        frame_length = len(data)

    frame_length = max(
        0,
        min(int(frame_length), len(data)),
    )

    return data[:frame_length].hex(" ")


# ============================================================
# Linux HID eszközkeresés
# ============================================================

def parse_uevent(path: Path) -> dict:
    data = {}

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    data[key] = value
    except OSError:
        pass

    return data


def parse_hid_id(hid_id: str):
    parts = hid_id.split(":")
    if len(parts) != 3:
        return None, None

    vendor_id = parts[1][-4:].upper()
    product_id = parts[2][-4:].upper()
    return vendor_id, product_id


def scan_devices():
    devices = []
    root = Path("/sys/class/hidraw")

    if not root.exists():
        return devices

    for item in sorted(root.glob("hidraw*")):
        info = parse_uevent(item / "device" / "uevent")
        vendor_id, product_id = parse_hid_id(info.get("HID_ID", ""))

        if not vendor_id or not product_id:
            continue

        if vendor_id != ELITECH_VENDOR_ID or product_id != ELITECH_PRODUCT_ID:
            continue

        device_path = f"/dev/{item.name}"
        name = info.get("HID_NAME", "") or "Elitech RC-5"

        devices.append(
            {
                "path": device_path,
                "vendor_id": vendor_id,
                "product_id": product_id,
                "name": name,
                "serial": info.get("HID_UNIQ", ""),
                "physical_path": info.get("HID_PHYS", ""),
                "display_name": name,
                "can_readwrite": os.access(device_path, os.R_OK | os.W_OK),
            }
        )

    return devices


def find_device(device_path: str):
    for device in scan_devices():
        if device["path"] == device_path:
            return device
    return None


# ============================================================
# Elitech HID protokoll
# ============================================================

def build_get_parameter_frame(offset: int, length: int) -> bytes:
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen paramétercím.")

    if not 1 <= length <= 52:
        raise ValueError("Érvénytelen lekérdezési hossz.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        0x03,  # GetParameter
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        length & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)
    return packet + bytes(64 - len(packet))


def drain_hid(fd: int):
    while True:
        try:
            data = os.read(fd, 64)
            if not data:
                return
        except BlockingIOError:
            return


def parse_response(response: bytes):
    if len(response) < 12:
        raise ValueError("Túl rövid HID válasz.")

    if response[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError("Érvénytelen Elitech válaszfejléc.")

    if response[4] != 0x03:
        raise ValueError(
            f"Váratlan Elitech műveleti kód: 0x{response[4]:02X}"
        )

    frame_length = response[3]

    if frame_length < 12:
        raise ValueError("Érvénytelen válaszméret.")

    if frame_length > len(response):
        raise ValueError("A HID válasz nem érkezett meg teljesen.")

    frame = response[:frame_length]

    expected_checksum = sum(frame[:-1]) & 0xFF
    actual_checksum = frame[-1]

    if actual_checksum != expected_checksum:
        raise ValueError(
            f"Hibás válasz-checksum: "
            f"0x{actual_checksum:02X} != 0x{expected_checksum:02X}"
        )

    offset = (frame[9] << 16) | (frame[7] << 8) | frame[8]
    data_length = frame[10]

    if 11 + data_length > frame_length - 1:
        raise ValueError("Csonka Elitech adatmező.")

    data = frame[11 : 11 + data_length]
    return offset, data


def hid_get_parameter(
    fd: int,
    offset: int,
    length: int,
    timeout: float = 1.0,
) -> bytes:
    drain_hid(fd)

    packet = build_get_parameter_frame(offset, length)

    LOGGER.debug(
        "HID GET TX | offset=0x%06X | len=%d | frame=%s",
        offset,
        length,
        frame_hex(packet, 12),
    )

    written = os.write(fd, packet)

    if written != len(packet):
        raise OSError("Nem sikerült elküldeni a teljes HID csomagot.")

    readable, _, _ = select.select([fd], [], [], timeout)

    if not readable:
        LOGGER.error(
            "HID GET TIMEOUT | offset=0x%06X | len=%d",
            offset,
            length,
        )
        raise TimeoutError(
            f"Az RC-5 nem válaszolt a 0x{offset:02X} lekérdezésre."
        )

    response = os.read(fd, 64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.debug(
        "HID GET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    response_offset, data = parse_response(response)

    requested_start = offset
    requested_end = offset + length
    response_start = response_offset
    response_end = response_offset + len(data)

    if requested_start < response_start or requested_end > response_end:
        raise ValueError(
            "Az RC-5 nem a kért paramétertartományt küldte vissza."
        )

    start = requested_start - response_start
    result = data[start : start + length]

    LOGGER.debug(
        "HID GET DATA | requested=0x%06X..0x%06X | "
        "response_offset=0x%06X | data=%s",
        requested_start,
        requested_end - 1,
        response_offset,
        result.hex(" "),
    )

    return result


def prime_parameter_session(
    fd: int,
    context: str,
    timeout: float = 1.0,
):
    """
    Visszaállítja / inicializálja az RC-5 normál 0x03 paraméterolvasási
    munkamenetét.

    A 246c:9001 / protocol 0x35 eszközön a GetRecord letöltési flow
    után megfigyeltük, hogy a rövid GetParameter olvasások egy része
    átmenetileg kizárólag 0xFF sentinel adatot ad vissza.

    Az "Eszköz információk" tab ezt következetesen helyreállítja,
    mert az első két lekérdezése:
        0x000000 / 14 byte  -- identity
        0x000094 / 2 byte   -- protocol

    A v21 ugyanezt explicit session-prime-ként használja, így a
    konfiguráció, rekordolvasás és mentés nem függ attól, melyik
    UI tabot nyitotta meg előtte a felhasználó.

    Ez kizárólag READ művelet.
    """
    identity = hid_get_parameter(
        fd,
        0x00,
        14,
        timeout=timeout,
    )

    protocol_data = hid_get_parameter(
        fd,
        0x94,
        2,
        timeout=timeout,
    )

    model = int.from_bytes(
        identity[0:2],
        byteorder="big",
    )

    serial = (
        identity[2:14]
        .decode("ascii", errors="replace")
        .replace("\x00", "")
        .strip()
    )

    protocol_version = (
        protocol_data[1]
        if len(protocol_data) >= 2
        else None
    )

    LOGGER.info(
        "PARAMETER SESSION PRIME | context=%s | model=0x%04X | "
        "serial=%s | protocol=%s",
        context,
        model,
        serial or "-",
        (
            f"0x{protocol_version:02X}"
            if protocol_version is not None
            else "-"
        ),
    )

    return identity, protocol_data


# ============================================================
# Adatdekódolás
# ============================================================

def decode_datetime(data: bytes) -> str:
    """
    Elitech 7-byte dátum/idő mező.

    Az új 246c:9001 RC-5 leállított állapotban több runtime mezőt
    0xFF sentinel értékekkel tölt ki. Ezeket nem szabad valódi
    dátumként megjeleníteni.

    A 3. byte .NET DayOfWeek; azt a dátum összeállításánál nem
    használjuk, így önmagában 0xFF lehet anélkül, hogy a dátum hibás lenne.
    """
    if len(data) != 7:
        return "-"

    if all(byte == 0 for byte in data):
        return "-"

    if all(byte == 0xFF for byte in data):
        return "-"

    # A tényleges datetime mezők: YY, MM, DD, hh, mm, ss.
    relevant = (
        data[0],
        data[1],
        data[3],
        data[4],
        data[5],
        data[6],
    )

    if any(byte == 0xFF for byte in relevant):
        return "-"

    try:
        dt = datetime(
            year=2000 + data[0],
            month=data[1],
            day=data[3],
            hour=data[4],
            minute=data[5],
            second=data[6],
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "-"


def decode_capacity_record_count(
    capacity_data: bytes,
    protocol_version: int,
) -> tuple[int | None, int | None]:
    """
    A 0x42 blokk kapacitás/rekordszám értelmezése.

    A normál 246c:9001 állapotban:
        00 00 7d 00 00 00 00 1b 00 00
        -> capacity 32000, records 27

    Leállítás után ugyanez megfigyelten:
        ff ff 7d 00 00 00 00 1b ff ff

    A felső FF FF ebben az állapotban sentinel/állapotkitöltés,
    nem a kapacitás része. Ezért az új hardvernél az FF FF xxxx
    mintát a megmaradó alsó 16 bitből normalizáljuk.

    Ha a szükséges mező teljesen FF, nem gyártunk belőle
    4 294 967 295-ös "adatot": None lesz, és a szigorú olvasó
    újrapróbálja / biztonságosan leáll.
    """
    if len(capacity_data) != 10:
        raise ValueError(
            f"Érvénytelen 0x42 blokkhossz: {len(capacity_data)}."
        )

    capacity_bytes = capacity_data[0:4]

    if capacity_bytes == b"\xFF\xFF\xFF\xFF":
        capacity = None
    elif (
        capacity_bytes[0:2] == b"\xFF\xFF"
        and capacity_bytes[2:4] != b"\xFF\xFF"
    ):
        capacity = int.from_bytes(
            capacity_bytes[2:4],
            byteorder="big",
        )

        LOGGER.debug(
            "CAPACITY STOP-STATE NORMALIZE | raw=%s | normalized=%d",
            capacity_bytes.hex(" "),
            capacity,
        )
    else:
        capacity = int.from_bytes(
            capacity_bytes,
            byteorder="big",
        )

    if protocol_version >= 0x24:
        record_bytes = capacity_data[4:8]
    else:
        record_bytes = capacity_data[6:8]

    if all(byte == 0xFF for byte in record_bytes):
        record_count = None
    else:
        record_count = int.from_bytes(
            record_bytes,
            byteorder="big",
        )

    # Lehetetlen kombinációt ne mutassunk felhasználói adatként.
    if (
        capacity is not None
        and record_count is not None
        and record_count > capacity
    ):
        LOGGER.warning(
            "CAPACITY/COUNT INCONSISTENT | raw=%s | "
            "capacity=%s | record_count=%s",
            capacity_data.hex(" "),
            capacity,
            record_count,
        )
        return None, None

    return capacity, record_count


def decode_interval_seconds(data: bytes) -> int | None:
    """
    2-byte mintavételi intervallum; 10 másodperces egység.

    FF FF runtime sentinelként nem valódi 10922,5 perc.
    """
    if len(data) != 2:
        return None

    if data == b"\xFF\xFF":
        return None

    raw = int.from_bytes(
        data,
        byteorder="big",
    )

    if raw == 0:
        return None

    return raw * 10


def format_optional_count(
    value: int | None,
    suffix: str = "",
) -> str:
    if value is None:
        return "-"

    formatted = f"{value:,}".replace(",", " ")

    return formatted + suffix


def decode_start_mode(byte: int) -> str:
    value = byte & 0b111
    modes = {
        0b000: "Azonnali",
        0b001: "Kézi",
        0b010: "Időzített",
        0b111: "Ismeretlen / MAX",
    }
    return modes.get(value, f"Ismeretlen (0b{value:03b})")


def decode_stop_mode(byte: int) -> str:
    value = byte & 0b111
    modes = {
        0b000: "Kézi",
        0b011: "Ideiglenes leállítás",
        0b111: "Nincs érvényes leállítás / MAX",
    }
    return modes.get(value, f"Ismeretlen (0b{value:03b})")


def format_interval(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600} óra"

    if seconds % 60 == 0:
        return f"{seconds // 60} perc"

    return f"{seconds} másodperc"


# ============================================================
# Eszköz információk
# ============================================================

def read_device_info(device_path: str):
    with HID_LOCK:
        fd = os.open(device_path, os.O_RDWR | os.O_NONBLOCK)

        try:
            identity = hid_get_parameter(fd, 0x00, 14)
            protocol_data = hid_get_parameter(fd, 0x94, 2)
            start_mode_data = hid_get_parameter(fd, 0x20, 1)
            device_state_data = hid_get_parameter(fd, 0x25, 1)
            stop_battery_data = hid_get_parameter(fd, 0x26, 2)
            configuration_time_data = hid_get_parameter(fd, 0x28, 7)
            start_stop_data = hid_get_parameter(fd, 0x30, 15)
            capacity_data = hid_get_parameter(fd, 0x42, 10)
            interval_data = hid_get_parameter(fd, 0x4C, 2)
            device_time_data = hid_get_parameter(fd, 0x88, 7)
        finally:
            os.close(fd)

    model = int.from_bytes(identity[0:2], byteorder="big")

    serial_number = (
        identity[2:14]
        .decode("ascii", errors="replace")
        .replace("\x00", "")
        .strip()
    )

    protocol_version = protocol_data[1]

    capacity, record_count = decode_capacity_record_count(
        capacity_data,
        protocol_version,
    )

    interval_seconds = decode_interval_seconds(
        interval_data
    )

    start_mode_byte = start_mode_data[0]
    device_state = device_state_data[0]
    actual_stop_byte = stop_battery_data[0]

    battery_byte = stop_battery_data[1]

    battery_raw = (
        None
        if battery_byte == 0xFF
        else battery_byte & 0x0F
    )

    configuration_time = decode_datetime(configuration_time_data)
    start_time = decode_datetime(start_stop_data[0:7])
    stop_time = decode_datetime(start_stop_data[8:15])
    device_time = decode_datetime(device_time_data)

    fields = [
        {"label": "Sorozatszám", "value": serial_number or "Nincs adat"},
        {"label": "Modellkód", "value": f"0x{model:04X}"},
        {"label": "Protokollverzió", "value": f"0x{protocol_version:02X}"},
        {
            "label": "Logger kapacitása",
            "value": format_optional_count(
                capacity,
                " mérés",
            ),
        },
        {
            "label": "Tárolt mérések száma",
            "value": format_optional_count(
                record_count,
            ),
        },
        {"label": "Mérés kezdési ideje", "value": start_time},
        {"label": "Mérés leállítási ideje", "value": stop_time},
        {"label": "Konfigurálás időpontja", "value": configuration_time},
        {"label": "Készülék ideje", "value": device_time},
        {
            "label": "Mintavételi időköz",
            "value": (
                "-"
                if interval_seconds is None
                else (
                    f"{format_interval(interval_seconds)} "
                    f"({interval_seconds} s)"
                )
            ),
        },
        {"label": "Indítási mód", "value": decode_start_mode(start_mode_byte)},
        {
            "label": "Gombos leállítás",
            "value": "Engedélyezve"
            if start_mode_byte & (1 << 3)
            else "Letiltva",
        },
        {
            "label": "Szoftveres leállítás",
            "value": "Engedélyezve"
            if start_mode_byte & (1 << 4)
            else "Letiltva",
        },
        {
            "label": "Eszközállapot",
            "value": f"0x{device_state:02X} (nyers érték)",
        },
        {
            "label": "Tényleges leállítási mód",
            "value": decode_stop_mode(actual_stop_byte),
        },
        {
            "label": "Elemállapot",
            "value": (
                "-"
                if battery_raw is None
                else f"{battery_raw} / 15 (nyers érték)"
            ),
        },
    ]

    return {
        "path": device_path,
        "serial_number": serial_number,
        "capacity": capacity,
        "record_count": record_count,
        "fields": fields,
    }



# ============================================================
# Konfiguráció írás / olvasás
# ============================================================

def build_set_parameter_frame(offset: int, data: bytes) -> bytes:
    """
    Elitech SetParameter (0x0004) HID frame.
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen paramétercím.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("A konfigurációs adatnak bytes típusúnak kell lennie.")

    if not 1 <= len(data) <= 52:
        raise ValueError("Érvénytelen konfigurációs adathossz.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x00,  # frame length, alább kitöltjük
        0x04,  # SetParameter
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        len(data) & 0xFF,
    ]

    frame.extend(data)
    frame[3] = len(frame) + 1
    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)

    if len(packet) > 64:
        raise ValueError("A HID csomag túl nagy.")

    return packet + bytes(64 - len(packet))


def parse_set_response(response: bytes, requested_offset: int):
    """
    SetParameter válasz ellenőrzése.
    Az ismert Elitech protokollban a válasz egyetlen státuszbájtot
    tartalmaz; 1 = siker.
    """
    if len(response) < 13:
        raise ValueError("Túl rövid SetParameter válasz.")

    if response[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError("Érvénytelen Elitech válaszfejléc.")

    if response[4] != 0x04:
        raise ValueError(
            f"Váratlan Elitech műveleti kód: 0x{response[4]:02X}"
        )

    frame_length = response[3]

    if frame_length < 13 or frame_length > len(response):
        raise ValueError("Érvénytelen SetParameter válaszméret.")

    frame = response[:frame_length]

    expected_checksum = sum(frame[:-1]) & 0xFF
    actual_checksum = frame[-1]

    if actual_checksum != expected_checksum:
        raise ValueError(
            f"Hibás SetParameter checksum: "
            f"0x{actual_checksum:02X} != 0x{expected_checksum:02X}"
        )

    response_offset = (
        (frame[9] << 16)
        | (frame[7] << 8)
        | frame[8]
    )

    if response_offset != requested_offset:
        raise ValueError(
            f"A válasz címe eltér a kért címtől: "
            f"0x{response_offset:06X} != 0x{requested_offset:06X}"
        )

    if frame[10] != 1:
        raise ValueError(
            f"Váratlan SetParameter státuszhossz: {frame[10]}"
        )

    if frame[11] != 1:
        raise RuntimeError(
            f"Az RC-5 elutasította a konfiguráció írását "
            f"(státusz: 0x{frame[11]:02X})."
        )



def build_official_set_packet(
    offset: int,
    data: bytes,
    *,
    declared_length: int | None = None,
    frame_length: int | None = None,
) -> bytes:
    """
    ElitechLog Win V8.0.5.0 DataFactory.GetListForSet() packet layout.

    Normally:
        frame_length = 11 + len(data) + 1
        declared_length = len(data)

    One factory packet is intentionally odd:
        offset 0x60:
          declared length = 0x30 (48)
          actual payload bytes = 47 (0x60..0x8E)
          frame length = 0x3B (59)
          checksum at byte 58

    We reproduce that byte-for-byte instead of "fixing" it.
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen paramétercím.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("A konfigurációs adatnak bytes típusúnak kell lennie.")

    if declared_length is None:
        declared_length = len(data)

    if frame_length is None:
        frame_length = 11 + len(data) + 1

    if not 0 <= declared_length <= 0xFF:
        raise ValueError("Érvénytelen deklarált adathossz.")

    if frame_length != 11 + len(data) + 1:
        raise ValueError(
            "A frame_length nem egyezik a tényleges Elitech frame méretével."
        )

    frame = [
        0x33,
        0xCC,
        0x00,
        frame_length & 0xFF,
        0x04,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        declared_length & 0xFF,
    ]

    frame.extend(data)
    frame.append(sum(frame) & 0xFF)

    if len(frame) != frame_length:
        raise RuntimeError("Belső hiba: hibás Elitech frame hossz.")

    if len(frame) > 64:
        raise ValueError("A HID csomag túl nagy.")

    return bytes(frame) + bytes(64 - len(frame))


def hid_set_parameter_official(
    fd: int,
    offset: int,
    data: bytes,
    *,
    declared_length: int | None = None,
    frame_length: int | None = None,
    timeout: float = 1.0,
):
    """
    ElitechLog V8.0.5.0 által generált SetParameter frame elküldése.
    """
    drain_hid(fd)

    packet = build_official_set_packet(
        offset,
        data,
        declared_length=declared_length,
        frame_length=frame_length,
    )

    LOGGER.info(
        "FACTORY SET TX | offset=0x%06X | declared_len=%d | "
        "actual_data_len=%d | frame_len=%d | data=%s",
        offset,
        packet[10],
        len(data),
        packet[3],
        data.hex(" "),
    )

    LOGGER.debug(
        "FACTORY SET TX FRAME | offset=0x%06X | frame=%s",
        offset,
        frame_hex(packet, packet[3]),
    )

    written = os.write(fd, packet)

    if written != len(packet):
        raise OSError("Nem sikerült elküldeni a teljes HID csomagot.")

    readable, _, _ = select.select([fd], [], [], timeout)

    if not readable:
        raise TimeoutError(
            f"Az RC-5 nem válaszolt a 0x{offset:02X} konfigurációírásra."
        )

    response = os.read(fd, 64)

    response_len = response[3] if len(response) >= 4 else len(response)

    LOGGER.info(
        "FACTORY SET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    parse_set_response(response, offset)

    LOGGER.info(
        "FACTORY SET ACK OK | offset=0x%06X",
        offset,
    )


def encode_official_elitech_datetime(value: datetime) -> bytes:
    """
    ElitechLog V8.0.5.0 DataFactory.GetListForSet() formátuma.

    A 3. byte NEM reserved:
    a gyári program System.DateTime.DayOfWeek értékét írja ide
    (Sunday=0 ... Saturday=6).

    A korábbi saját kódunk itt 0-t írt, ami eltért a gyári programtól.
    """
    if value.year < 2000 or value.year > 2255:
        raise ValueError("A dátum éve nem ábrázolható az RC-5 formátumában.")

    # Python weekday(): Monday=0 ... Sunday=6
    # .NET DayOfWeek: Sunday=0 ... Saturday=6
    dotnet_day_of_week = (value.weekday() + 1) % 7

    return bytes(
        [
            value.year - 2000,
            value.month,
            dotnet_day_of_week,
            value.day,
            value.hour,
            value.minute,
            value.second,
        ]
    )


def hid_set_parameter(
    fd: int,
    offset: int,
    data: bytes,
    timeout: float = 1.0,
):
    drain_hid(fd)

    packet = build_set_parameter_frame(offset, data)

    LOGGER.info(
        "HID SET TX | offset=0x%06X | len=%d | data=%s",
        offset,
        len(data),
        data.hex(" "),
    )

    LOGGER.debug(
        "HID SET TX FRAME | offset=0x%06X | frame=%s",
        offset,
        frame_hex(packet, packet[3]),
    )

    written = os.write(fd, packet)

    if written != len(packet):
        raise OSError("Nem sikerült elküldeni a teljes HID csomagot.")

    readable, _, _ = select.select([fd], [], [], timeout)

    if not readable:
        LOGGER.error(
            "HID SET TIMEOUT | offset=0x%06X | len=%d",
            offset,
            len(data),
        )
        raise TimeoutError(
            f"Az RC-5 nem válaszolt a 0x{offset:02X} konfigurációírásra."
        )

    response = os.read(fd, 64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.info(
        "HID SET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    parse_set_response(response, offset)

    LOGGER.info(
        "HID SET ACK OK | offset=0x%06X",
        offset,
    )



def build_generic_command_frame(
    operation: int,
    offset: int = 0,
    data: bytes = b"\x00",
) -> bytes:
    """
    Generic Elitech command frame.

    The public python-elitech reverse engineering lists:
      0x02C0 = FormatCommand
      0x03C0 = StopCommand

    The operation is encoded little-endian in bytes 4..5.
    """
    if not 0 <= operation <= 0xFFFF:
        raise ValueError("Érvénytelen Elitech műveleti kód.")

    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen Elitech cím.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("A parancs adata bytes típusú legyen.")

    if len(data) > 52:
        raise ValueError("Túl hosszú Elitech parancsadat.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x00,
        operation & 0xFF,
        (operation >> 8) & 0xFF,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        len(data) & 0xFF,
    ]

    frame.extend(data)
    frame[3] = len(frame) + 1
    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)

    if len(packet) > 64:
        raise ValueError("A HID csomag túl nagy.")

    return packet + bytes(64 - len(packet))


def hid_generic_command(
    fd: int,
    operation: int,
    *,
    offset: int = 0,
    data: bytes = b"\x00",
    timeout: float = 2.0,
) -> bytes:
    """
    Küld egy nem-SetParameter Elitech parancsot és a nyers választ adja vissza.
    """
    drain_hid(fd)

    packet = build_generic_command_frame(
        operation,
        offset,
        data,
    )

    LOGGER.warning(
        "HID GENERIC TX | op=0x%04X | offset=0x%06X | frame=%s",
        operation,
        offset,
        frame_hex(packet, packet[3]),
    )

    written = os.write(fd, packet)

    if written != len(packet):
        raise OSError(
            "Nem sikerült elküldeni a teljes Elitech parancsot."
        )

    readable, _, _ = select.select(
        [fd],
        [],
        [],
        timeout,
    )

    if not readable:
        LOGGER.warning(
            "HID GENERIC NO RESPONSE | op=0x%04X",
            operation,
        )
        return b""

    response = os.read(fd, 64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.warning(
        "HID GENERIC RX | op=0x%04X | raw=%s",
        operation,
        frame_hex(response, response_len),
    )

    return response


def hid_format_command(fd: int) -> bytes:
    """
    KÍSÉRLETI finalizálási teszt.

    0x02C0 a python-elitech forrásban FormatCommand néven szerepel.
    Ez törölheti a mérési memóriát, ezért csak akkor hívható, ha
    a record_count előzetesen pontosan 0.
    """
    return hid_generic_command(
        fd,
        0x02C0,
        offset=0,
        data=b"\x00",
        timeout=2.0,
    )


def encode_device_datetime(value: datetime) -> bytes:
    if value.year < 2000 or value.year > 2255:
        raise ValueError("A dátum éve nem ábrázolható az RC-5 formátumában.")

    return bytes(
        [
            value.year - 2000,
            value.month,
            0x00,
            value.day,
            value.hour,
            value.minute,
            value.second,
        ]
    )


def read_record_count_from_fd(fd: int):
    """
    Biztonsági szempontból kritikus olvasás.

    A stopped RC-5 0xFF sentineljeit normalizáljuk. Ha három
    egymást követő olvasásból sem kapunk hihető capacity/count
    párost, inkább hibát adunk, mint hogy 0xFFFFFFFF-et valódi
    rekordszámként használjunk egy destruktív mentés előtt.
    """
    protocol_data = hid_get_parameter(
        fd,
        0x94,
        2,
    )

    protocol_version = protocol_data[1]

    last_raw = None

    for attempt in range(1, 4):
        capacity_data = hid_get_parameter(
            fd,
            0x42,
            10,
        )

        last_raw = capacity_data

        capacity, record_count = (
            decode_capacity_record_count(
                capacity_data,
                protocol_version,
            )
        )

        if (
            capacity is not None
            and record_count is not None
        ):
            if attempt > 1:
                LOGGER.info(
                    "RECORD COUNT RETRY RECOVERED | attempt=%d | "
                    "capacity=%d | records=%d",
                    attempt,
                    capacity,
                    record_count,
                )

            return (
                protocol_version,
                capacity,
                record_count,
            )

        LOGGER.warning(
            "RECORD COUNT INVALID/SENTINEL | attempt=%d/3 | raw=%s",
            attempt,
            capacity_data.hex(" "),
        )

        time.sleep(0.06)

    raise RuntimeError(
        "A logger kapacitás/rekordszám mezője jelenleg "
        "nem értelmezhető biztonságosan "
        f"(utolsó nyers 0x42 blokk: "
        f"{last_raw.hex(' ') if last_raw else '-'}). "
        "A konfiguráció mentését ezért nem engedjük."
    )



# ============================================================
# Mérési rekordok kiolvasása
# ============================================================

RECORD_LENGTH = 8
RECORDS_PER_PACKET = 6
RECORD_RESPONSE_DATA_OFFSET = 11

RECORD_FLAG_MARK = 0x01
RECORD_FLAG_PAUSE = 0x02
RECORD_FLAG_STOP = 0x04
RECORD_FLAG_SIGN1 = 0x08
RECORD_FLAG_LIGHT = 0x10
RECORD_FLAG_VIBRATION = 0x20
RECORD_FLAG_SIGN2 = 0x40
RECORD_FLAG_ERROR = 0x80


# ElitechLog Win V8.0.5.0 DataFactory.GetListForParameter()
# pontos, statikusan visszafejtett 17 darabos kapcsolódási/read preamble.
#
# A gyári program nem csak a régi 0x0003 GetParameter műveletet használja,
# hanem több 0x0005 read packetet is elküld minden első csatlakozáskor.
# Ezek olvasási műveletek; a v16 a rekordletöltés előtt reprodukálja őket.
OFFICIAL_PARAMETER_PREAMBLE = (
    (0x03, 0x000000, 0x30),
    (0x03, 0x000030, 0x30),
    (0x03, 0x000060, 0x30),
    (0x03, 0x000090, 0x08),
    (0x03, 0x000098, 0x34),
    (0x03, 0x0000CC, 0x30),

    (0x05, 0x000000, 0x20),
    (0x05, 0x000070, 0x10),
    (0x05, 0x000080, 0x30),
    (0x05, 0x0000B0, 0x30),
    (0x05, 0x0000E0, 0x30),
    (0x05, 0x000110, 0x30),
    (0x05, 0x000140, 0x30),
    (0x05, 0x000020, 0x30),
    (0x05, 0x000050, 0x20),

    (0x03, 0x00012C, 0x30),
    (0x03, 0x0000FD, 0x30),
)


def build_official_read_frame(
    operation: int,
    offset: int,
    length: int,
) -> bytes:
    """
    ElitechLog GetListForParameter()-kompatibilis 12-byte request,
    64 byte-ra nullával feltöltve.

    operation jelenleg 0x03 vagy 0x05.
    """
    if operation not in (0x03, 0x05):
        raise ValueError("Nem támogatott read operation.")

    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen read offset.")

    if not 1 <= length <= 0xFF:
        raise ValueError("Érvénytelen read length.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        operation,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        length & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    return bytes(frame) + bytes(64 - len(frame))


def run_official_parameter_preamble(
    fd: int,
    timeout: float = 1.0,
) -> None:
    """
    A gyári ElitechLog első kapcsolódáskor végrehajtott 17 read packetes
    paraméterpreambluma.

    Fontos:
      - nincs write/config módosítás;
      - minden packet után megvárjuk a választ;
      - a gyári kód 80 ms szünetet tart a packetek között, ezt megtartjuk.
    """
    LOGGER.info(
        "FACTORY READ PREAMBLE START | packets=%d",
        len(OFFICIAL_PARAMETER_PREAMBLE),
    )

    # A korábbi API GET-ekből esetleg bent maradt reportokat egyszer,
    # dokumentáltan kiürítjük. Rekordpacketek között már NEM drainelünk.
    drained = 0

    while True:
        readable, _, _ = select.select(
            [fd],
            [],
            [],
            0,
        )

        if not readable:
            break

        try:
            old = os.read(fd, 64)
        except BlockingIOError:
            break

        if not old:
            break

        drained += 1

        LOGGER.debug(
            "FACTORY READ PREAMBLE DRAIN | raw=%s",
            old.hex(" "),
        )

    LOGGER.debug(
        "FACTORY READ PREAMBLE DRAINED | reports=%d",
        drained,
    )

    for index, (
        operation,
        offset,
        length,
    ) in enumerate(
        OFFICIAL_PARAMETER_PREAMBLE,
        start=1,
    ):
        packet = build_official_read_frame(
            operation,
            offset,
            length,
        )

        LOGGER.debug(
            "FACTORY READ TX | n=%d/%d | op=0x%02X | "
            "offset=0x%06X | len=%d | frame=%s",
            index,
            len(OFFICIAL_PARAMETER_PREAMBLE),
            operation,
            offset,
            length,
            frame_hex(packet, packet[3]),
        )

        written = os.write(fd, packet)

        if written != len(packet):
            raise OSError(
                "Nem sikerült elküldeni a gyári read preamble packetet."
            )

        readable, _, _ = select.select(
            [fd],
            [],
            [],
            timeout,
        )

        if not readable:
            raise TimeoutError(
                "Az RC-5 nem válaszolt a gyári paraméter-read "
                f"preamble {index}. packetére "
                f"(op=0x{operation:02X}, offset=0x{offset:06X})."
            )

        response = os.read(fd, 64)

        LOGGER.debug(
            "FACTORY READ RX | n=%d/%d | op=0x%02X | "
            "offset=0x%06X | raw=%s",
            index,
            len(OFFICIAL_PARAMETER_PREAMBLE),
            operation,
            offset,
            response.hex(" "),
        )

        # A gyári UsbCommand.GetParameter() Thread.Sleep(80)-at használ.
        time.sleep(0.08)

    LOGGER.info("FACTORY READ PREAMBLE COMPLETE")


def build_get_record_frame(
    offset: int,
    count: int = RECORDS_PER_PACKET,
) -> bytes:
    """
    ElitechLog Win V8.0.5.0 DataFactory.GetListForRecord() request.

    A gyári kliensnél:
      - offset = rekordsorszám (0, 6, 12, ...)
      - standard 8-byte rekordnál count = 6
      - operation = 0x0001
      - byte[5] = 0 a normál rekordtárhoz
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Érvénytelen rekordoffset.")

    if not 1 <= count <= 0xFF:
        raise ValueError("Érvénytelen rekorddarabszám.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        0x01,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        count & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    return bytes(frame) + bytes(64 - len(frame))


def is_record_ack_only(
    report: bytes,
) -> bool:
    """
    Az új 246c:9001 eszközön megfigyelt azonnali GetRecord ACK:

      33 cc 00 0c 01 00 00 00 00 00 00 0c 00 00 ...

    Ez nem mérési adat. A v15 tévesen rekordpacketként próbálta parse-olni.
    """
    if len(report) < 12:
        return False

    if report[0:5] != bytes(
        [0x33, 0xCC, 0x00, 0x0C, 0x01]
    ):
        return False

    checksum_ok = (
        report[11]
        == (sum(report[:11]) & 0xFF)
    )

    no_payload = all(
        value == 0
        for value in report[12:]
    )

    return checksum_ok and no_payload


def validate_record_report_header(
    report: bytes,
) -> None:
    if len(report) != 64:
        raise ValueError(
            f"A HID report nem 64 byte: {len(report)}."
        )

    if report[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError(
            "Érvénytelen GetRecord report header."
        )

    if report[4] != 0x01:
        raise ValueError(
            "A GetRecord report operation byte-ja nem 0x01."
        )


def parse_elitech_record(
    raw: bytes,
    protocol_version: int,
) -> dict | None:
    """
    Elitech 8-byte standard rekord dekódolás.

    Az új 246c:9001 / protocol 0x35 RC-5 hardveren a szabályos
    mérési rekordok byte0 értéke következetesen 0xC0.

    A régi flag-térkép ezt 0x80=Error + 0x40=Sign2 kombinációnak
    értelmezte, ezért a v16 minden normál rekordot tévesen
    "Hiba" állapotúnak mutatott.

    Protocol >= 0x35 esetén ezért a felső két bitet az új
    rekordformátum markerének kezeljük; az alsó 6 bit esemény/sign
    flagjeit továbbra is megtartjuk.

    Az RC-5 hőmérséklet-only modellnél a humidity bitek nem
    szenzoradatok, ezért páratartalmat nem jelenítünk meg.
    """
    if len(raw) != RECORD_LENGTH:
        raise ValueError(
            f"Érvénytelen rekordhossz: {len(raw)}."
        )

    if raw == bytes([0xFF]) * RECORD_LENGTH:
        return None

    flags_raw = raw[0]

    if protocol_version >= 0x35:
        flags = flags_raw & 0x3F
        format_marker = flags_raw & 0xC0
    else:
        flags = flags_raw
        format_marker = 0

    second = (raw[1] >> 2) & 0x3F
    year = 2000 + (raw[2] & 0x7F)

    month = (
        ((raw[3] & 0x07) << 1)
        + ((raw[2] >> 7) & 0x01)
    )

    day = (raw[3] >> 3) & 0x1F
    hour = raw[4] & 0x1F
    minute = raw[6] & 0x3F

    if protocol_version >= 0x23:
        temperature_raw = (
            (((raw[1] >> 1) & 0x01) << 11)
            + (raw[5] << 3)
            + (raw[4] >> 5)
        )
    else:
        temperature_raw = (
            (raw[5] << 3)
            + (raw[4] >> 5)
        )

    temperature = temperature_raw / 10.0

    if flags & RECORD_FLAG_SIGN1:
        temperature = -temperature

    timestamp = datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
    )

    flag_labels = []

    if flags & RECORD_FLAG_MARK:
        flag_labels.append("Jelölés")

    if flags & RECORD_FLAG_LIGHT:
        flag_labels.append("Fény")

    if flags & RECORD_FLAG_VIBRATION:
        flag_labels.append("Rezgés")

    if flags & RECORD_FLAG_PAUSE:
        status = "Szünet"
    elif flags & RECORD_FLAG_STOP:
        status = "Leállítás"
    elif (
        protocol_version < 0x35
        and flags & RECORD_FLAG_ERROR
    ):
        status = "Hiba"
    else:
        status = "Mérés"

    temperature_value = (
        temperature
        if status == "Mérés"
        else None
    )

    humidity_value = None

    return {
        "timestamp": timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "temperature": temperature_value,
        "humidity": humidity_value,
        "status": status,
        "flags": flag_labels,
        "flags_raw": flags_raw,
        "flags_effective": flags,
        "record_format_marker": format_marker,
        "raw_hex": raw.hex(" "),
    }


def count_plausible_records(
    report: bytes,
    protocol_version: int,
) -> int:
    """
    Diagnosztikai klasszifikáció: hány 8-byte rekord parse-olható
    érvényes dátummal a report byte 11-től?
    """
    plausible = 0

    for local_index in range(RECORDS_PER_PACKET):
        start = (
            RECORD_RESPONSE_DATA_OFFSET
            + local_index * RECORD_LENGTH
        )
        end = start + RECORD_LENGTH

        raw = report[start:end]

        try:
            parsed = parse_elitech_record(
                raw,
                protocol_version,
            )
        except (
            ValueError,
            OverflowError,
        ):
            continue

        if parsed is not None:
            plausible += 1

    return plausible


def read_one_hid_report(
    fd: int,
    timeout: float,
) -> bytes | None:
    readable, _, _ = select.select(
        [fd],
        [],
        [],
        timeout,
    )

    if not readable:
        return None

    response = os.read(fd, 64)

    if not response:
        return None

    return response


def get_record_data_report(
    fd: int,
    offset: int,
    protocol_version: int,
    timeout: float = 1.5,
) -> bytes:
    """
    GetRecord kérés + az új hardveren megfigyelt ACK/data szétválasztás.

    A v15 minden rekordkérés elején drain_hid()-ot hívott. Ha az eszköz
    az azonnali ACK után néhány ms-mal küldi a tényleges adatreportot,
    a következő packet előtti drain ezt észrevétlenül eldobhatta.

    A v16 ezért:
      1. nem drainel packetek között;
      2. ACK után még vár ugyanazon kéréshez tartozó új reportot;
      3. minden beérkező 64 byte-ot teljesen naplóz.
    """
    packet = build_get_record_frame(
        offset,
        RECORDS_PER_PACKET,
    )

    LOGGER.debug(
        "HID RECORD GET TX | offset=%d | count=%d | frame=%s",
        offset,
        RECORDS_PER_PACKET,
        frame_hex(packet, packet[3]),
    )

    written = os.write(fd, packet)

    if written != len(packet):
        raise OSError(
            "Nem sikerült elküldeni a teljes GetRecord HID csomagot."
        )

    deadline = time.monotonic() + timeout
    report_number = 0
    saw_ack = False

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            break

        response = read_one_hid_report(
            fd,
            min(remaining, 0.35),
        )

        if response is None:
            if saw_ack:
                # ACK után rövid ideig nincs új report; folytatjuk a
                # teljes timeout végéig, nem küldünk közben új offsetet.
                continue
            continue

        report_number += 1

        LOGGER.debug(
            "HID RECORD RX STREAM | offset=%d | report_no=%d | "
            "len=%d | raw=%s",
            offset,
            report_number,
            len(response),
            response.hex(" "),
        )

        try:
            validate_record_report_header(response)
        except ValueError as error:
            LOGGER.warning(
                "HID RECORD NONSTANDARD REPORT | offset=%d | "
                "report_no=%d | error=%s",
                offset,
                report_number,
                error,
            )
            continue

        if is_record_ack_only(response):
            saw_ack = True

            LOGGER.info(
                "HID RECORD ACK ONLY | offset=%d | "
                "waiting for data report without draining",
                offset,
            )

            continue

        plausible = count_plausible_records(
            response,
            protocol_version,
        )

        LOGGER.debug(
            "HID RECORD DATA CANDIDATE | offset=%d | "
            "plausible_records=%d",
            offset,
            plausible,
        )

        if plausible > 0:
            return response

        LOGGER.warning(
            "HID RECORD REPORT WITHOUT PLAUSIBLE DATA | "
            "offset=%d | raw=%s",
            offset,
            response.hex(" "),
        )

    if saw_ack:
        raise TimeoutError(
            "A GetRecord ACK megérkezett, de utána nem érkezett "
            "mérési adatreport. A v16 logban a teljes gyári read "
            "preamble és az ACK utáni report-stream is látszik."
        )

    raise TimeoutError(
        "Az RC-5 nem válaszolt a mérési rekord lekérésére."
    )


def read_device_records(
    device_path: str,
    limit: int = 500,
):
    """
    Mérési rekordok read-only kiolvasása.

    A v16 két, az ElitechLog V8.0.5.0-ból visszafejtett részt
    reprodukál:
      - teljes 17-packetes kapcsolódási paraméter-read preamble;
      - 6 rekord / GetRecord packet.

    Emellett kezeli az új 246c:9001 hardveren megfigyelt külön
    ACK-only reportot anélkül, hogy a késve érkező reportot drainelné.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValueError(
            "A rekordlimit egész szám legyen."
        )

    if limit < 0 or limit > 32000:
        raise ValueError(
            "A rekordlimit 0 és 32000 között lehet."
        )

    LOGGER.info(
        "RECORD READ REQUEST | version=%s | device=%s | limit=%d",
        APP_VERSION,
        device_path,
        limit,
    )

    with HID_LOCK:
        fd = os.open(
            device_path,
            os.O_RDWR | os.O_NONBLOCK,
        )

        try:
            prime_parameter_session(
                fd,
                context="record-read-precheck",
            )

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            if record_count > capacity:
                raise RuntimeError(
                    "A logger rekordszáma nagyobb a kapacitásnál."
                )

            if record_count == 0:
                return {
                    "protocol_version": protocol_version,
                    "capacity": capacity,
                    "stored_count": 0,
                    "loaded_count": 0,
                    "start_index": None,
                    "end_index": None,
                    "records": [],
                }

            if limit == 0:
                wanted_start = 0
            else:
                wanted_start = max(
                    0,
                    record_count - limit,
                )

            first_packet_offset = (
                wanted_start // RECORDS_PER_PACKET
            ) * RECORDS_PER_PACKET

            LOGGER.info(
                "RECORD READ PRECHECK | protocol=0x%02X | "
                "capacity=%d | stored=%d | wanted_start=%d | "
                "first_packet_offset=%d",
                protocol_version,
                capacity,
                record_count,
                wanted_start,
                first_packet_offset,
            )

            # A gyári ElitechLog kapcsolódási read sorozata.
            run_official_parameter_preamble(fd)

            parsed_records = []
            packet_offset = first_packet_offset

            while packet_offset < record_count:
                response = get_record_data_report(
                    fd,
                    packet_offset,
                    protocol_version,
                )

                valid_in_packet = min(
                    RECORDS_PER_PACKET,
                    record_count - packet_offset,
                )

                for local_index in range(valid_in_packet):
                    record_index = (
                        packet_offset + local_index
                    )

                    raw_start = (
                        RECORD_RESPONSE_DATA_OFFSET
                        + local_index * RECORD_LENGTH
                    )

                    raw_end = raw_start + RECORD_LENGTH

                    raw = response[raw_start:raw_end]

                    LOGGER.debug(
                        "RECORD RAW | index=%d | packet_offset=%d | "
                        "local=%d | raw=%s",
                        record_index + 1,
                        packet_offset,
                        local_index,
                        raw.hex(" "),
                    )

                    try:
                        parsed = parse_elitech_record(
                            raw,
                            protocol_version,
                        )

                        if parsed is None:
                            item = {
                                "index": record_index + 1,
                                "timestamp": None,
                                "temperature": None,
                                "humidity": None,
                                "status": "Nincs adat",
                                "flags": [],
                                "flags_raw": 0,
                                "raw_hex": raw.hex(" "),
                            }
                        else:
                            parsed["index"] = record_index + 1
                            item = parsed

                    except (
                        ValueError,
                        OverflowError,
                    ) as error:
                        LOGGER.warning(
                            "RECORD PARSE ERROR | index=%d | "
                            "raw=%s | error=%s",
                            record_index + 1,
                            raw.hex(" "),
                            error,
                        )

                        item = {
                            "index": record_index + 1,
                            "timestamp": None,
                            "temperature": None,
                            "humidity": None,
                            "status": "Értelmezési hiba",
                            "flags": [],
                            "flags_raw": None,
                            "raw_hex": raw.hex(" "),
                            "parse_error": str(error),
                        }

                    if record_index >= wanted_start:
                        parsed_records.append(item)

                packet_offset += RECORDS_PER_PACKET

        finally:
            # A GetRecord flow után a firmware paraméterolvasási állapota
            # ezen az új hardveren nem mindig tér vissza magától.
            # Még ugyanazon HID handle-en visszaprime-oljuk, így a
            # következő tabváltás nem kap FF sentinel blokkokat.
            try:
                time.sleep(0.05)

                prime_parameter_session(
                    fd,
                    context="record-read-cleanup",
                    timeout=0.75,
                )

                LOGGER.info(
                    "RECORD SESSION CLEANUP COMPLETE"
                )
            except Exception as cleanup_error:
                # A rekordok sikeres kiolvasását ne veszítsük el csak azért,
                # mert pl. a felhasználó közben kihúzta az USB-t. A következő
                # high-level művelet saját prime-mal indul.
                LOGGER.warning(
                    "RECORD SESSION CLEANUP FAILED | %s: %s",
                    cleanup_error.__class__.__name__,
                    cleanup_error,
                )
            finally:
                os.close(fd)

    valid_measurements = sum(
        1
        for record in parsed_records
        if (
            record.get("status") == "Mérés"
            and record.get("temperature") is not None
        )
    )

    LOGGER.info(
        "RECORD READ RESULT | version=%s | stored=%d | loaded=%d | "
        "valid_measurements=%d | first_index=%s | last_index=%s",
        APP_VERSION,
        record_count,
        len(parsed_records),
        valid_measurements,
        (
            parsed_records[0]["index"]
            if parsed_records
            else "-"
        ),
        (
            parsed_records[-1]["index"]
            if parsed_records
            else "-"
        ),
    )

    return {
        "protocol_version": protocol_version,
        "capacity": capacity,
        "stored_count": record_count,
        "loaded_count": len(parsed_records),
        "start_index": (
            parsed_records[0]["index"]
            if parsed_records
            else None
        ),
        "end_index": (
            parsed_records[-1]["index"]
            if parsed_records
            else None
        ),
        "records": parsed_records,
    }


def read_device_config(device_path: str):
    """
    A jelenleg támogatott konfigurációs mezők beolvasása.

    Nincs periodikus háttérlekérdezés: ezt az API-t a UI csak a tab
    megnyitásakor vagy kézi újraolvasáskor hívja.
    """
    LOGGER.info(
        "CONFIG READ REQUEST | device=%s",
        device_path,
    )

    with HID_LOCK:
        fd = os.open(
            device_path,
            os.O_RDWR | os.O_NONBLOCK,
        )

        try:
            prime_parameter_session(
                fd,
                context="config-read",
            )

            start_mode_data = hid_get_parameter(fd, 0x20, 1)
            configuration_time_data = hid_get_parameter(fd, 0x28, 7)
            interval_data = hid_get_parameter(fd, 0x4C, 2)
            device_time_data = hid_get_parameter(fd, 0x88, 7)

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            interval_seconds = decode_interval_seconds(
                interval_data
            )

            if interval_seconds is None:
                LOGGER.warning(
                    "CONFIG INTERVAL SENTINEL | direct=%s | "
                    "trying 0x30 full-block fallback",
                    interval_data.hex(" "),
                )

                block_30 = hid_get_parameter(
                    fd,
                    0x30,
                    0x30,
                )

                # 0x4C - 0x30 = 0x1C
                fallback_interval = block_30[
                    0x1C:0x1E
                ]

                interval_seconds = decode_interval_seconds(
                    fallback_interval
                )

                LOGGER.info(
                    "CONFIG INTERVAL FALLBACK | raw=%s | seconds=%s",
                    fallback_interval.hex(" "),
                    interval_seconds,
                )
        finally:
            os.close(fd)

    start_byte = start_mode_data[0]
    if interval_seconds is None:
        raise RuntimeError(
            "A mintavételi időköz jelenleg nem olvasható ki "
            "megbízhatóan. A mentést biztonsági okból nem engedjük."
        )

    LOGGER.info(
        "CONFIG READ RESULT | device=%s | protocol=0x%02X | "
        "records=%d | interval_seconds=%d | start_byte=0x%02X | "
        "device_time=%s | configuration_time=%s",
        device_path,
        protocol_version,
        record_count,
        interval_seconds,
        start_byte,
        decode_datetime(device_time_data),
        decode_datetime(configuration_time_data),
    )

    return {
        "path": device_path,
        "protocol_version": protocol_version,
        "capacity": capacity,
        "record_count": record_count,
        "interval_seconds": interval_seconds,
        "interval_minutes": interval_seconds / 60.0,
        "start_mode_raw": start_byte & 0b111,
        "start_mode": decode_start_mode(start_byte),
        "button_stop": bool(start_byte & (1 << 3)),
        "software_stop": bool(start_byte & (1 << 4)),
        "configuration_time": decode_datetime(configuration_time_data),
        "device_time": decode_datetime(device_time_data),
        "can_configure": True,
        "requires_data_loss_confirmation": record_count > 0,
        "blocked_reason": (
            ""
            if record_count == 0
            else (
                f"A logger {record_count} tárolt mérési rekordot tartalmaz. "
                "A konfiguráció mentése a gyári FormatCommand miatt ezeket "
                "törli. A mentés csak kettős, szándékos megerősítés után "
                "engedélyezett."
            )
        ),
    }



ELITECH_COMPAT_RANGES = [
    (0x00, 0x30),
    (0x30, 0x30),
    (0x60, 0x30),
    (0x98, 0x34),
    (0xCC, 0x30),
    (0xFD, 0x2F),
]

# ElitechLog Win V8.0.5.0:
# UsbCommand.Initval() protocol >= 0x16 esetén 6 SetParameter packetet
# küld, majd FormatCommand-ot. A 7. (device-name) packet csak az arra
# képes modelleknél kerül sorra.
ELITECH_CONFIG_WRITE_RANGES = [
    (0x00, 0x30),
    (0x30, 0x30),
    (0x60, 0x30),
    (0x98, 0x34),
    (0xCC, 0x30),
    (0xFD, 0x2F),
]


def _patch_compat_config_blocks(
    blocks,
    *,
    interval_minutes: int,
    button_stop: bool,
    software_stop: bool,
    sync_clock: bool,
):
    """
    A gyári ElitechLog save-flow alapján készítjük elő a hat blokkot.

    A már érvényes eszközkonfigurációt alapnak használjuk, és csak:
      - 0x20 start/stop bitek,
      - 0x28..0x2E konfigurációs idő,
      - 0x4C..0x4D mintavételi intervallum,
      - 0x88..0x8E device-time staging mező
    változik.

    A gyári ElitechLog a 0x88..0x8E mezőt NULLÁZZA SetParameter során.
    """
    by_start = {
        start: bytearray(data)
        for start, data in blocks.items()
    }

    interval_seconds = interval_minutes * 60
    interval_raw = interval_seconds // 10

    block0 = by_start[0x00]

    old_start = block0[0x20]
    new_start = old_start & 0b11100000
    new_start |= 0b001  # Manual

    if button_stop:
        new_start |= 1 << 3

    if software_stop:
        new_start |= 1 << 4

    block0[0x20] = new_start

    if sync_clock:
        now = datetime.now().replace(microsecond=0)
        encoded = encode_official_elitech_datetime(now)
        block0[0x28:0x2F] = encoded

    block1 = by_start[0x30]
    interval_pos = 0x4C - 0x30
    block1[
        interval_pos : interval_pos + 2
    ] = int(interval_raw).to_bytes(
        2,
        byteorder="big",
    )

    # A gyári GetListForSet() packet 0x60 ezt explicit nullázza.
    block2 = by_start[0x60]
    device_time_pos = 0x88 - 0x60
    block2[
        device_time_pos : device_time_pos + 7
    ] = bytes(7)

    return {
        start: bytes(data)
        for start, data in by_start.items()
    }


def apply_device_config(
    device_path: str,
    *,
    interval_minutes: int,
    sync_clock: bool,
    button_stop: bool,
    software_stop: bool,
    allow_data_loss: bool = False,
    expected_record_count: int | None = None,
):
    """
    ElitechLog Win V8.0.5.0 save-flow rekonstrukció.

    A statikus .NET visszafejtés alapján a gyári program:
      1. 6 db SetParameter packetet küld,
      2. a dátum 3. byte-jába DayOfWeek értéket ír,
      3. a 0x60 packetben nullázza 0x88..0x8E-t,
      4. a harmadik SetParameter packetnek van egy gyári off-by-one
         framing sajátossága,
      5. elküldi a 0x02C0 FormatCommand-ot,
      6. kb. 500 ms-ig nyitva hagyja az eszközt,
      7. csak utána zárja a HID kapcsolatot.

    Ezt a sorrendet reprodukáljuk.
    """
    try:
        interval_minutes = int(interval_minutes)
    except (TypeError, ValueError):
        raise ValueError(
            "A mintavételi időköz csak egész perc lehet."
        )

    if interval_minutes < 1 or interval_minutes > 1440:
        raise ValueError(
            "A mintavételi időköz 1 és 1440 perc között lehet."
        )

    interval_seconds = interval_minutes * 60

    if interval_seconds % 10 != 0:
        raise ValueError(
            "Az RC-5 mintavételi időközének 10 másodperces "
            "egységre kell illeszkednie."
        )

    interval_raw = interval_seconds // 10

    if interval_raw > 0xFFFF:
        raise ValueError(
            "A mintavételi időköz túl nagy az RC-5 számára."
        )

    LOGGER.info(
        "FACTORY FLOW START | version=%s | device=%s | interval_minutes=%d | "
        "sync_clock=%s | button_stop=%s | software_stop=%s | "
        "allow_data_loss=%s | expected_record_count=%s",
        APP_VERSION,
        device_path,
        interval_minutes,
        sync_clock,
        button_stop,
        software_stop,
        allow_data_loss,
        expected_record_count,
    )

    expected_start_byte = None
    expected_config_time = None

    with HID_LOCK:
        fd = os.open(
            device_path,
            os.O_RDWR | os.O_NONBLOCK,
        )

        try:
            prime_parameter_session(
                fd,
                context="factory-save-precheck",
            )

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            LOGGER.info(
                "FACTORY PRECHECK | protocol=0x%02X | "
                "capacity=%d | records=%d",
                protocol_version,
                capacity,
                record_count,
            )

            if expected_record_count is not None:
                try:
                    expected_record_count = int(expected_record_count)
                except (TypeError, ValueError):
                    raise RuntimeError(
                        "Érvénytelen expected_record_count érték."
                    )

                if record_count != expected_record_count:
                    raise RuntimeError(
                        "A logger rekordszáma megváltozott a jóváhagyás óta: "
                        f"a felület {expected_record_count} rekordot erősített meg, "
                        f"de a készülék most {record_count} rekordot jelent. "
                        "Olvasd újra a konfigurációt, majd erősítsd meg újra."
                    )

            if record_count != 0 and not allow_data_loss:
                raise RuntimeError(
                    f"A logger {record_count} tárolt mérési rekordot tartalmaz. "
                    "A FormatCommand ezeket törölheti. A backend csak explicit "
                    "allow_data_loss=true jóváhagyással engedi ezt a műveletet."
                )

            if record_count != 0:
                LOGGER.warning(
                    "DESTRUCTIVE CONFIG CONFIRMED | records_to_erase=%d | "
                    "expected_record_count=%s",
                    record_count,
                    expected_record_count,
                )

            if protocol_version < 0x16:
                raise RuntimeError(
                    "Ez a gyári hat-packetes save-flow csak "
                    "0x16 vagy újabb protokollverzióhoz használható."
                )

            original_blocks = {}

            for start, length in ELITECH_CONFIG_WRITE_RANGES:
                original_blocks[start] = hid_get_parameter(
                    fd,
                    start,
                    length,
                )

            patched_blocks = _patch_compat_config_blocks(
                original_blocks,
                interval_minutes=interval_minutes,
                button_stop=button_stop,
                software_stop=software_stop,
                sync_clock=sync_clock,
            )

            for start, length in ELITECH_CONFIG_WRITE_RANGES:
                old_data = original_blocks[start]
                new_data = patched_blocks[start]

                diffs = []

                for index, (old_byte, new_byte) in enumerate(
                    zip(old_data, new_data)
                ):
                    if old_byte != new_byte:
                        diffs.append(
                            f"0x{start + index:02X}:"
                            f"{old_byte:02X}->{new_byte:02X}"
                        )

                LOGGER.info(
                    "FACTORY BLOCK DIFF | start=0x%02X | "
                    "len=%d | changes=%s",
                    start,
                    length,
                    ", ".join(diffs) if diffs else "(none)",
                )

            expected_start_byte = patched_blocks[0x00][0x20]

            if sync_clock:
                expected_config_time = patched_blocks[0x00][0x28:0x2F]

            # ------------------------------------------------
            # Exact factory packet order.
            # ------------------------------------------------

            hid_set_parameter_official(
                fd,
                0x00,
                patched_blocks[0x00],
            )

            hid_set_parameter_official(
                fd,
                0x30,
                patched_blocks[0x30],
            )

            # ElitechLog V8.0.5.0 DataFactory.GetListForSet():
            # byte[3] = 0x3B, byte[10] = 0x30, but checksum is at 58.
            # Therefore only addresses 0x60..0x8E (47 bytes) are in frame.
            hid_set_parameter_official(
                fd,
                0x60,
                patched_blocks[0x60][:47],
                declared_length=48,
                frame_length=59,
            )

            hid_set_parameter_official(
                fd,
                0x98,
                patched_blocks[0x98],
            )

            hid_set_parameter_official(
                fd,
                0xCC,
                patched_blocks[0xCC],
            )

            hid_set_parameter_official(
                fd,
                0xFD,
                patched_blocks[0xFD],
            )

            LOGGER.warning(
                "FACTORY FORMAT TX | op=0x02C0"
            )

            format_response = hid_format_command(fd)

            LOGGER.warning(
                "FACTORY FORMAT RX | response_len=%d",
                len(format_response),
            )

            # CUSB.setParameters(): success után Thread.Sleep(500),
            # majd Dispose/CloseDevice. Eddig mi túl korán zártunk.
            LOGGER.info(
                "FACTORY POST-FORMAT HOLD | keeping HID open for 550 ms"
            )
            time.sleep(0.55)

        finally:
            os.close(fd)

        LOGGER.info(
            "FACTORY HID CLOSED | waiting 1 second before reopen"
        )
        time.sleep(1.0)

        fd = os.open(
            device_path,
            os.O_RDWR | os.O_NONBLOCK,
        )

        try:
            verify_start = hid_get_parameter(fd, 0x20, 1)[0]
            verify_interval = int.from_bytes(
                hid_get_parameter(fd, 0x4C, 2),
                byteorder="big",
            )
            verify_config_time = hid_get_parameter(fd, 0x28, 7)
            verify_device_time = hid_get_parameter(fd, 0x88, 7)

        finally:
            os.close(fd)

    LOGGER.info(
        "FACTORY REOPEN VERIFY | interval_raw=%d | "
        "interval_minutes=%.3f | start_byte=0x%02X | "
        "config_time_raw=%s | config_time=%s | "
        "device_time_raw=%s | device_time=%s",
        verify_interval,
        verify_interval * 10 / 60,
        verify_start,
        verify_config_time.hex(" "),
        decode_datetime(verify_config_time),
        verify_device_time.hex(" "),
        decode_datetime(verify_device_time),
    )

    problems = []

    if verify_interval != interval_raw:
        problems.append(
            "a mintavételi időköz az újranyitáskor nem egyezik"
        )

    if (
        verify_start & 0b00011111
    ) != (
        expected_start_byte & 0b00011111
    ):
        problems.append(
            "a start/stop bitek az újranyitáskor nem egyeznek"
        )

    if (
        sync_clock
        and expected_config_time is not None
        and verify_config_time != expected_config_time
    ):
        problems.append(
            "a konfigurációs idő az újranyitáskor nem egyezik"
        )

    if problems:
        raise RuntimeError(
            "A gyári save-flow rekonstrukció már a szoftveres "
            "újranyitás után eltért: "
            + "; ".join(problems)
        )

    return {
        "ok": True,
        "message": (
            "A gyári ElitechLog V8.0.5.0 save-flow rekonstrukció "
            "lefutott, és a HID újranyitása után az értékek még "
            "megmaradtak. A végső NVM-teszt: húzd ki fizikailag az "
            "RC-5-öt, várj 3 másodpercet, dugd vissza, majd olvasd "
            "újra az Eszköz információkat."
        ),
        "write_mode": "elitechlog-v8.0.5.0-factory-flow",
        "protocol_version": protocol_version,
        "capacity": capacity,
        "record_count_before_save": record_count,
        "data_loss_confirmed": bool(record_count != 0 and allow_data_loss),
        "interval_minutes": interval_minutes,
        "start_mode": "Kézi",
        "button_stop": bool(button_stop),
        "software_stop": bool(software_stop),
        "clock_sync_requested": bool(sync_clock),
        "device_time": decode_datetime(verify_device_time),
        "configuration_time": decode_datetime(verify_config_time),
        "persistence_note": (
            "Fontos: ez még csak szoftveres HID újranyitásos ellenőrzés. "
            "A nem felejtő memória csak fizikai USB kihúzás/visszadugás "
            "után igazolható."
        ),
    }


# ============================================================
# udev jogosultság beállítása
# ============================================================

UDEV_RULE = (
    'KERNEL=="hidraw*", '
    'ATTRS{idVendor}=="246c", '
    'ATTRS{idProduct}=="9001", '
    'MODE="0660", '
    'TAG+="uaccess"\n'
)


def install_udev_rule():
    pkexec = shutil.which("pkexec")
    udevadm = shutil.which("udevadm")
    install_cmd = shutil.which("install")

    if not pkexec:
        raise RuntimeError(
            "A pkexec nem található. Telepítsd a policykit-1 csomagot, "
            "vagy állíts be kézzel udev szabályt."
        )

    if not udevadm:
        raise RuntimeError("Az udevadm nem található.")

    if not install_cmd:
        raise RuntimeError("Az install parancs nem található.")

    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="99-elitech-rc5-",
            suffix=".rules",
            delete=False,
        ) as handle:
            handle.write(UDEV_RULE)
            tmp_path = handle.name

        command = (
            f"{shlex.quote(install_cmd)} -m 0644 "
            f"{shlex.quote(tmp_path)} "
            f"/etc/udev/rules.d/99-elitech-rc5.rules"
            " && "
            f"{shlex.quote(udevadm)} control --reload-rules"
            " && "
            f"{shlex.quote(udevadm)} trigger --subsystem-match=hidraw"
        )

        result = subprocess.run(
            [pkexec, "/bin/sh", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            if not message:
                message = (
                    "A jogosultság beállítása megszakadt vagy sikertelen volt."
                )
            raise RuntimeError(message)

        return {
            "ok": True,
            "message": (
                "Az udev szabály telepítve. "
                "Ha az eszköz továbbra sem olvasható, húzd ki és dugd vissza az RC-5-öt."
            ),
        }

    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ============================================================
# Web UI
# ============================================================

HTML = r"""
<!doctype html>
<html lang="hu">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Elitech RC-5 Manager</title>

<style>
* { box-sizing: border-box; }

html, body { height: 100%; }

body {
    margin: 0;
    background: #f3f4f6;
    color: #172033;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

button, input { font: inherit; }

.app {
    min-height: 100vh;
    padding: 18px;
}

.header { margin-bottom: 16px; }

.header h1 {
    margin: 0;
    font-size: 28px;
}

.subtitle {
    margin-top: 3px;
    color: #667085;
    font-size: 14px;
}

.layout {
    display: grid;
    grid-template-columns: minmax(220px, 1fr) minmax(0, 5fr);
    gap: 16px;
    align-items: start;
}

.sidebar, .main-panel { min-width: 0; }

.panel {
    background: white;
    border: 1px solid #d8dce3;
    border-radius: 10px;
}

.sidebar-panel { padding: 12px; }

.sidebar-title {
    margin: 0 0 10px;
    font-size: 14px;
}

.device-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
    max-height: 520px;
    overflow-y: auto;
}

.device-list-empty {
    padding: 12px 10px;
    border: 1px dashed #cfd4dc;
    border-radius: 7px;
    color: #7b8491;
    font-size: 13px;
    text-align: center;
}

.device-item {
    width: 100%;
    padding: 10px;
    border: 1px solid #cfd4dc;
    border-radius: 7px;
    background: #fff;
    color: #172033;
    text-align: left;
    cursor: pointer;
}

.device-item:hover {
    background: #f6f8fb;
    border-color: #aeb8c7;
}

.device-item.selected {
    border-color: #2457d6;
    background: #eef3ff;
    box-shadow: inset 3px 0 0 #2457d6;
}

.device-item-name {
    display: block;
    margin-bottom: 4px;
    font-size: 13px;
    font-weight: 700;
    overflow-wrap: anywhere;
}

.device-item-meta {
    display: block;
    color: #6f7783;
    font-family: monospace;
    font-size: 11px;
    overflow-wrap: anywhere;
}

.device-status {
    margin-top: 10px;
    font-size: 12px;
    line-height: 1.4;
}

.device-status.online { color: #16823b; }
.device-status.offline { color: #a43737; }

.tabs {
    display: flex;
    gap: 4px;
    padding: 0 14px;
    border-bottom: 1px solid #d8dce3;
}

.tab-button {
    padding: 14px 10px 11px;
    border: 0;
    border-bottom: 3px solid transparent;
    background: transparent;
    color: #596274;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
}

.tab-button.active {
    border-bottom-color: #2457d6;
    color: #172033;
}

.tab-content {
    min-height: 480px;
    padding: 18px;
}

.tab-page { display: none; }
.tab-page.active { display: block; }

.empty-state {
    display: flex;
    min-height: 420px;
    align-items: center;
    justify-content: center;
    color: #747b86;
    text-align: center;
}

.content-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
}

.content-title { min-width: 0; }

.content-title h2 {
    margin: 0 0 3px;
    font-size: 19px;
}

.device-path {
    color: #737b87;
    font-family: monospace;
    font-size: 12px;
}

.action-button {
    padding: 8px 12px;
    border: 1px solid #aeb4bf;
    border-radius: 6px;
    background: white;
    cursor: pointer;
}

.action-button:hover { background: #f5f6f8; }

.action-button:disabled {
    color: #999;
    cursor: default;
}

.loading {
    display: none;
    margin-bottom: 12px;
    color: #69717c;
    font-size: 13px;
}

.error-box,
.permission-box,
.success-box,
.warning-box {
    display: none;
    margin-bottom: 12px;
    padding: 12px;
    border-radius: 8px;
    line-height: 1.45;
}

.error-box {
    border: 1px solid #e0a3a3;
    background: #fff4f4;
    color: #8b2222;
    white-space: pre-wrap;
}

.permission-box {
    border: 1px solid #e2c06d;
    background: #fff9e8;
    color: #6a5111;
}

.success-box {
    border: 1px solid #9ac7a7;
    background: #f1fbf4;
    color: #245f34;
}

.warning-box {
    border: 1px solid #e2c06d;
    background: #fff9e8;
    color: #6a5111;
}

.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
}

.info-item {
    min-width: 0;
    padding: 12px;
    border: 1px solid #e0e3e8;
    border-radius: 8px;
    background: #fafbfc;
}

.info-label {
    margin-bottom: 5px;
    color: #667085;
    font-size: 12px;
}

.info-value {
    overflow-wrap: anywhere;
    font-family: monospace;
    font-size: 14px;
    font-weight: 650;
}

/* konfiguráció */
.config-intro {
    margin-bottom: 14px;
    padding: 12px;
    border: 1px solid #cbd7ef;
    border-radius: 8px;
    background: #f5f8ff;
    color: #39465f;
    font-size: 13px;
    line-height: 1.5;
}

.config-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.config-section {
    min-width: 0;
    padding: 14px;
    border: 1px solid #e0e3e8;
    border-radius: 8px;
    background: #fafbfc;
}

.config-section.full-width {
    grid-column: 1 / -1;
}

.config-section h3 {
    margin: 0 0 12px;
    font-size: 15px;
}

.form-row {
    display: grid;
    grid-template-columns: minmax(150px, 0.8fr) minmax(180px, 1.2fr);
    gap: 12px;
    align-items: center;
    margin-bottom: 11px;
}

.form-row:last-child { margin-bottom: 0; }

.form-row label {
    color: #4f5968;
    font-size: 13px;
}

.form-control {
    width: 100%;
    min-width: 0;
    height: 38px;
    padding: 0 9px;
    border: 1px solid #b8bec8;
    border-radius: 6px;
    background: white;
    color: #172033;
}

.form-control:disabled {
    background: #eef0f3;
    color: #707783;
}

.inline-unit {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 8px;
    align-items: center;
}

.checkbox-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 34px;
    color: #394150;
    font-size: 13px;
}

.checkbox-row input {
    width: 16px;
    height: 16px;
}

.hint {
    margin-top: 5px;
    color: #7a828d;
    font-size: 11px;
    line-height: 1.4;
}

.preview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 9px;
}

.preview-item {
    padding: 10px;
    border: 1px solid #e1e5eb;
    border-radius: 7px;
    background: white;
}

.preview-label {
    margin-bottom: 4px;
    color: #6f7783;
    font-size: 11px;
}

.preview-value {
    font-family: monospace;
    font-size: 14px;
    font-weight: 700;
}

.config-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
}

.config-footer-text {
    max-width: 760px;
    color: #5e6673;
    font-size: 12px;
    line-height: 1.5;
}

.save-button {
    flex: 0 0 auto;
    padding: 10px 15px;
    border: 1px solid #2457d6;
    border-radius: 6px;
    background: #2457d6;
    color: white;
    font-weight: 700;
    cursor: pointer;
}

.save-button:hover { background: #1d48b4; }

.save-button:disabled {
    border-color: #c7ccd4;
    background: #eceef1;
    color: #8a919c;
    cursor: not-allowed;
}

.status-value-ok { color: #167c3b; }
.status-value-blocked { color: #a43737; }


.measurement-toolbar {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
    margin-bottom: 16px;
}

.measurement-toolbar-group {
    display: flex;
    align-items: end;
    gap: 10px;
    flex-wrap: wrap;
}

.measurement-control {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.measurement-control label {
    color: #5e6673;
    font-size: 12px;
    font-weight: 700;
}

.measurement-summary {
    margin: 14px 0;
}

.measurement-chart-wrap {
    display: none;
    margin: 16px 0;
    padding: 12px;
    border: 1px solid #e1e4e9;
    border-radius: 7px;
    background: #fff;
}

.measurement-chart-title {
    margin: 0 0 8px 0;
    font-size: 14px;
    font-weight: 700;
}

.measurement-chart {
    width: 100%;
    min-height: 260px;
}

.measurement-chart svg {
    display: block;
    width: 100%;
    height: auto;
    cursor: crosshair;
    user-select: none;
}

.measurement-chart-help {
    margin-top: 6px;
    color: #69717c;
    font-size: 12px;
}

.measurement-table-wrap {
    margin-top: 14px;
    overflow: auto;
    max-height: 560px;
    border: 1px solid #e1e4e9;
    border-radius: 7px;
}

.measurement-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    background: #fff;
}

.measurement-table th,
.measurement-table td {
    padding: 8px 10px;
    border-bottom: 1px solid #eceef2;
    text-align: left;
    white-space: nowrap;
}

.measurement-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: #f4f6f8;
    color: #3d4652;
    font-size: 12px;
}

.measurement-table td.numeric {
    text-align: right;
    font-variant-numeric: tabular-nums;
}

.measurement-table tr:last-child td {
    border-bottom: none;
}

.measurement-table tr.event-row td {
    background: #fff9ec;
}

.measurement-table tr.error-row td {
    background: #fff0f0;
}

.measurement-empty {
    padding: 28px 12px;
    color: #69717c;
    text-align: center;
}

.measurement-note {
    color: #69717c;
    font-size: 12px;
    line-height: 1.45;
    margin-top: 9px;
}


.safety-modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: rgba(17, 24, 39, 0.58);
}

.safety-modal-backdrop.open {
    display: flex;
}

.safety-modal {
    width: min(620px, 100%);
    background: #fff;
    border: 1px solid #cfd4dc;
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);
    overflow: hidden;
}

.safety-modal-header {
    padding: 18px 20px 10px;
    font-size: 18px;
    font-weight: 750;
    color: #172033;
}

.safety-modal-body {
    padding: 0 20px 18px;
    color: #3e4857;
    line-height: 1.5;
    white-space: pre-line;
}

.safety-modal-actions {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 20px;
    border-top: 1px solid #e5e7eb;
    background: #f7f8fa;
}

.safety-modal-button {
    min-width: 116px;
    padding: 9px 16px;
    border: 1px solid #b9c0ca;
    border-radius: 7px;
    background: #fff;
    color: #172033;
    cursor: pointer;
    font-weight: 650;
}

.safety-modal-button:hover {
    background: #f2f4f7;
}

.safety-modal-button.danger {
    border-color: #b42318;
    background: #b42318;
    color: #fff;
}

.safety-modal-button.danger:hover {
    background: #912018;
}

@media (max-width: 1000px) {
    .config-grid { grid-template-columns: 1fr; }
    .config-section.full-width { grid-column: auto; }
}

@media (max-width: 850px) {
    .layout { grid-template-columns: 1fr; }
    .device-list { max-height: 220px; }
    .form-row { grid-template-columns: 1fr; gap: 5px; }
    .config-footer { align-items: stretch; flex-direction: column; }
}
</style>
</head>

<body>
<div class="app">

    <div class="header">
        <h1>Elitech RC-5 Manager <span style="font-size:13px;font-weight:600;opacity:.65;">v21-tab-session-recovery</span></h1>
        <div class="subtitle">USB HID eszközkezelő</div>
    </div>

    <div class="layout">

        <aside class="sidebar">
            <div class="panel sidebar-panel">
                <h2 class="sidebar-title">Elérhető eszközök</h2>

                <div id="deviceList" class="device-list">
                    <div class="device-list-empty">Eszközök keresése...</div>
                </div>

                <div id="deviceStatus" class="device-status offline">
                    Eszközök keresése...
                </div>
            </div>
        </aside>

        <main class="main-panel">
            <div class="panel">

                <div class="tabs">
                    <button id="infoTabButton" type="button" class="tab-button active">
                        Eszköz információk
                    </button>

                    <button id="configTabButton" type="button" class="tab-button">
                        Mérés konfigurálása
                    </button>

                    <button id="measurementsTabButton" type="button" class="tab-button">
                        Mérési eredmények
                    </button>
                </div>

                <div class="tab-content">

                    <section id="infoTabPage" class="tab-page active">
                        <div id="infoEmptyState" class="empty-state">
                            Válassz egy Elitech RC-5 eszközt a bal oldali listából.
                        </div>

                        <div id="infoContent" style="display:none;">
                            <div class="content-header">
                                <div class="content-title">
                                    <h2 id="selectedDeviceName">Elitech RC-5</h2>
                                    <div id="selectedDevicePath" class="device-path"></div>
                                </div>

                                <button
                                    id="refreshInfoButton"
                                    type="button"
                                    class="action-button"
                                >
                                    Frissítés
                                </button>
                            </div>

                            <div id="infoLoading" class="loading">
                                Adatok lekérdezése...
                            </div>

                            <div id="infoErrorBox" class="error-box"></div>

                            <div id="permissionBox" class="permission-box">
                                Az RC-5 felismerhető, de nincs megfelelő
                                HID-jogosultság.
                                <br><br>
                                <button
                                    id="permissionButton"
                                    type="button"
                                    class="action-button"
                                >
                                    USB-jogosultság beállítása
                                </button>
                            </div>

                            <div id="infoSuccessBox" class="success-box"></div>
                            <div id="infoGrid" class="info-grid"></div>
                        </div>
                    </section>


                    <section id="configTabPage" class="tab-page">

                        <div id="configEmptyState" class="empty-state">
                            Válassz egy Elitech RC-5 eszközt a bal oldali listából.
                        </div>

                        <div id="configContent" style="display:none;">
                            <div class="content-header">
                                <div class="content-title">
                                    <h2 id="configDeviceName">Elitech RC-5</h2>
                                    <div id="configDevicePath" class="device-path"></div>
                                </div>

                                <button
                                    id="reloadConfigButton"
                                    type="button"
                                    class="action-button"
                                >
                                    Beállítások újraolvasása
                                </button>
                            </div>

                            <div class="config-intro">
                                Ez a tab a logger előkészítésére szolgál.
                                <strong>A mérés mentés után sem indul el.</strong>
                                A program minden mentéskor kézi indítási módot állít be,
                                így a mérés külön, a készülék ▶ gombjával indítható.
                            </div>

                            <div id="configLoading" class="loading">
                                Konfiguráció beolvasása...
                            </div>

                            <div id="configErrorBox" class="error-box"></div>
                            <div id="configSuccessBox" class="success-box"></div>
                            <div id="configWarningBox" class="warning-box"></div>

                            <div id="configForm">

                                <div class="config-grid">

                                    <section class="config-section">
                                        <h3>Mintavétel</h3>

                                        <div class="form-row">
                                            <label for="sampleInterval">
                                                Mintavételi időköz
                                            </label>

                                            <div>
                                                <div class="inline-unit">
                                                    <input
                                                        id="sampleInterval"
                                                        class="form-control"
                                                        type="number"
                                                        min="1"
                                                        max="1440"
                                                        step="1"
                                                        value="30"
                                                    >
                                                    <span>perc</span>
                                                </div>

                                                <div class="hint">
                                                    A készülék 10 másodperces
                                                    felbontásban tárolja az intervallumot;
                                                    itt egész perceket használunk.
                                                </div>
                                            </div>
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Indítás</h3>

                                        <div class="form-row">
                                            <label>
                                                Indítási mód
                                            </label>

                                            <input
                                                class="form-control"
                                                value="Kézi — a készülék ▶ gombjával"
                                                disabled
                                            >
                                        </div>

                                        <div class="hint">
                                            Azonnali és időzített indítást szándékosan
                                            nem engedünk ezen a képernyőn, hogy a
                                            konfiguráció mentése ne indíthassa el a mérést.
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Készülék órája</h3>

                                        <div class="checkbox-row">
                                            <input
                                                id="syncClock"
                                                type="checkbox"
                                                checked
                                            >

                                            <label for="syncClock">
                                                Óra szinkronizálása a számítógép
                                                aktuális idejéhez mentéskor
                                            </label>
                                        </div>

                                        <div class="form-row">
                                            <label>
                                                Készülék jelenlegi ideje
                                            </label>

                                            <input
                                                id="currentDeviceTime"
                                                class="form-control"
                                                type="text"
                                                readonly
                                            >
                                        </div>

                                        <div class="form-row">
                                            <label>
                                                Számítógép ideje
                                            </label>

                                            <input
                                                id="computerTime"
                                                class="form-control"
                                                type="text"
                                                readonly
                                            >
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Leállítás engedélyezése</h3>

                                        <div class="checkbox-row">
                                            <input
                                                id="allowButtonStop"
                                                type="checkbox"
                                            >

                                            <label for="allowButtonStop">
                                                Leállítás engedélyezése a készülék gombjával
                                            </label>
                                        </div>

                                        <div class="checkbox-row">
                                            <input
                                                id="allowSoftwareStop"
                                                type="checkbox"
                                            >

                                            <label for="allowSoftwareStop">
                                                Szoftveres leállítás engedélyezése
                                            </label>
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Memória / biztonság</h3>

                                        <div class="preview-grid">
                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Logger kapacitása
                                                </div>
                                                <div id="configCapacity" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Tárolt mérések
                                                </div>
                                                <div id="configRecordCount" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Konfigurálható
                                                </div>
                                                <div id="configAllowed" class="preview-value">
                                                    —
                                                </div>
                                            </div>
                                        </div>

                                        <div class="hint">
                                            A program nem enged újrakonfigurálást, ha a
                                            logger már mérési rekordokat tartalmaz.
                                            A rekordok előbb a Mérési eredmények tabon
                                            olvashatók ki és exportálhatók.
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Tervezett mérés</h3>

                                        <div class="preview-grid">
                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Rekord / nap
                                                </div>
                                                <div id="recordsPerDay" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Rekord / év
                                                </div>
                                                <div id="recordsPerYear" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Memória becsült időtartama
                                                </div>
                                                <div id="memoryDuration" class="preview-value">
                                                    —
                                                </div>
                                            </div>
                                        </div>
                                    </section>


                                    <section class="config-section full-width">
                                        <h3>Konfiguráció alkalmazása</h3>

                                        <div class="config-footer">
                                            <div class="config-footer-text">
                                                Ez a verzió már nem a régi python-elitech mintáját követi,
                                                hanem az ElitechLog Win V8.0.5.0-ból statikusan
                                                visszafejtett gyári save-flow-t: 6 SetParameter
                                                packet, gyári dátumformátum, FormatCommand, majd
                                                500 ms-os nyitva tartás és HID újranyitás. Ha a logger
                                                már tartalmaz méréseket, a FormatCommand törölheti őket;
                                                ilyenkor a mentés csak kettős megerősítés után indul el.
                                            </div>

                                            <button
                                                id="saveConfigButton"
                                                type="button"
                                                class="save-button"
                                                disabled
                                            >
                                                Konfiguráció mentése
                                            </button>
                                        </div>
                                    </section>

                                </div>
                            </div>
                        </div>
                    </section>


                    <section id="measurementsTabPage" class="tab-page">

                        <div id="measurementsEmptyState" class="empty-state">
                            Válassz egy Elitech RC-5 eszközt a bal oldali listából.
                        </div>

                        <div id="measurementsContent" style="display:none;">
                            <div class="content-header">
                                <div class="content-title">
                                    <h2 id="measurementsDeviceName">Elitech RC-5</h2>
                                    <div id="measurementsDevicePath" class="device-path"></div>
                                </div>
                            </div>

                            <div class="config-intro">
                                A rekordok kiolvasása <strong>csak olvasási művelet</strong>.
                                A v16 a gyári ElitechLog V8.0.5.0 teljes
                                17-packetes kapcsolódási read preamble-ját is
                                reprodukálja, majd GetRecord packeteket küld.
                                Az új hardver ACK-only válaszait külön kezeli,
                                és nem dobja el a késve érkező HID reportokat.
                            </div>

                            <div class="measurement-toolbar">
                                <div class="measurement-toolbar-group">
                                    <div class="measurement-control">
                                        <label for="measurementLimit">
                                            Betöltendő rekordok
                                        </label>

                                        <select
                                            id="measurementLimit"
                                            class="form-control"
                                        >
                                            <option value="100">Utolsó 100</option>
                                            <option value="500" selected>Utolsó 500</option>
                                            <option value="2000">Utolsó 2000</option>
                                            <option value="0">Összes</option>
                                        </select>
                                    </div>

                                    <button
                                        id="reloadMeasurementsButton"
                                        type="button"
                                        class="action-button"
                                    >
                                        Mérések beolvasása
                                    </button>
                                </div>

                                <button
                                    id="exportCsvButton"
                                    type="button"
                                    class="action-button"
                                    disabled
                                >
                                    CSV letöltés
                                </button>
                            </div>

                            <div id="measurementsLoading" class="loading">
                                Mérési rekordok beolvasása...
                            </div>

                            <div id="measurementsErrorBox" class="error-box"></div>
                            <div id="measurementsSuccessBox" class="success-box"></div>

                            <div
                                id="measurementSummary"
                                class="preview-grid measurement-summary"
                            >
                                <div class="preview-item">
                                    <div class="preview-label">Tárolt rekord</div>
                                    <div id="measurementStoredCount" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Betöltve</div>
                                    <div id="measurementLoadedCount" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Időszak</div>
                                    <div id="measurementPeriod" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Minimum</div>
                                    <div id="measurementMin" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Átlag</div>
                                    <div id="measurementAvg" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Maximum</div>
                                    <div id="measurementMax" class="preview-value">—</div>
                                </div>
                            </div>

                            <div id="measurementChartWrap" class="measurement-chart-wrap">
                                <div class="measurement-chart-title">
                                    Hőmérséklet-idősor
                                </div>
                                <div id="measurementChart" class="measurement-chart"></div>
                                <div class="measurement-chart-help">
                                    Mozgasd az egeret a grafikon fölött a legközelebbi mérési pont kiemeléséhez.
                                </div>
                            </div>

                            <div class="measurement-table-wrap">
                                <table class="measurement-table">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>Időpont</th>
                                            <th>Hőmérséklet</th>
                                            <th>Páratartalom</th>
                                            <th>Állapot</th>
                                            <th>Jelzők</th>
                                        </tr>
                                    </thead>

                                    <tbody id="measurementTableBody">
                                        <tr>
                                            <td colspan="6" class="measurement-empty">
                                                Még nincs betöltött mérési adat.
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div class="measurement-note">
                                A táblázat és a CSV páratartalom-mezőt is megtart
                                a későbbi, páratartalom-képes Elitech modellekhez.
                                Ennél az RC-5-nél ez jelenleg „—”. A grafikon
                                időtengelye automatikusan alkalmazkodik a mérési
                                időszak hosszához, az egérrel pedig a legközelebbi
                                valódi adatpont emelhető ki.
                            </div>
                        </div>
                    </section>

                </div>
            </div>
        </main>
    </div>
</div>

<div
    id="safetyModalBackdrop"
    class="safety-modal-backdrop"
    aria-hidden="true"
>
    <div
        class="safety-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="safetyModalTitle"
    >
        <div
            id="safetyModalTitle"
            class="safety-modal-header"
        ></div>

        <div
            id="safetyModalBody"
            class="safety-modal-body"
        ></div>

        <div
            id="safetyModalActions"
            class="safety-modal-actions"
        ></div>
    </div>
</div>

<script>
const APP_TOKEN = "__APP_TOKEN__";

let devices = [];
let selectedDevicePath = "";
let activeTab = "info";

let infoBusy = false;
let configBusy = false;
let measurementsBusy = false;
let permissionBusy = false;

let currentCapacity = 32000;
let currentRecordCount = null;
let configLoaded = false;
let measurementsLoaded = false;
let loadedMeasurementRecords = [];


const deviceList = document.getElementById("deviceList");
const deviceStatus = document.getElementById("deviceStatus");

const infoTabButton = document.getElementById("infoTabButton");
const configTabButton = document.getElementById("configTabButton");
const measurementsTabButton = document.getElementById("measurementsTabButton");
const infoTabPage = document.getElementById("infoTabPage");
const configTabPage = document.getElementById("configTabPage");
const measurementsTabPage = document.getElementById("measurementsTabPage");

const infoEmptyState = document.getElementById("infoEmptyState");
const infoContent = document.getElementById("infoContent");
const selectedDeviceName = document.getElementById("selectedDeviceName");
const selectedDevicePathEl = document.getElementById("selectedDevicePath");
const refreshInfoButton = document.getElementById("refreshInfoButton");
const infoLoading = document.getElementById("infoLoading");
const infoErrorBox = document.getElementById("infoErrorBox");
const permissionBox = document.getElementById("permissionBox");
const permissionButton = document.getElementById("permissionButton");
const infoSuccessBox = document.getElementById("infoSuccessBox");
const infoGrid = document.getElementById("infoGrid");

const configEmptyState = document.getElementById("configEmptyState");
const configContent = document.getElementById("configContent");
const configDeviceName = document.getElementById("configDeviceName");
const configDevicePath = document.getElementById("configDevicePath");
const reloadConfigButton = document.getElementById("reloadConfigButton");
const configLoading = document.getElementById("configLoading");
const configErrorBox = document.getElementById("configErrorBox");
const configSuccessBox = document.getElementById("configSuccessBox");
const configWarningBox = document.getElementById("configWarningBox");

const sampleInterval = document.getElementById("sampleInterval");
const syncClock = document.getElementById("syncClock");
const currentDeviceTime = document.getElementById("currentDeviceTime");
const computerTime = document.getElementById("computerTime");
const allowButtonStop = document.getElementById("allowButtonStop");
const allowSoftwareStop = document.getElementById("allowSoftwareStop");
const configCapacity = document.getElementById("configCapacity");
const configRecordCount = document.getElementById("configRecordCount");
const configAllowed = document.getElementById("configAllowed");
const recordsPerDay = document.getElementById("recordsPerDay");
const recordsPerYear = document.getElementById("recordsPerYear");
const memoryDuration = document.getElementById("memoryDuration");
const saveConfigButton = document.getElementById("saveConfigButton");

const safetyModalBackdrop = document.getElementById("safetyModalBackdrop");
const safetyModalTitle = document.getElementById("safetyModalTitle");
const safetyModalBody = document.getElementById("safetyModalBody");
const safetyModalActions = document.getElementById("safetyModalActions");

const measurementsEmptyState = document.getElementById("measurementsEmptyState");
const measurementsContent = document.getElementById("measurementsContent");
const measurementsDeviceName = document.getElementById("measurementsDeviceName");
const measurementsDevicePath = document.getElementById("measurementsDevicePath");
const measurementLimit = document.getElementById("measurementLimit");
const reloadMeasurementsButton = document.getElementById("reloadMeasurementsButton");
const exportCsvButton = document.getElementById("exportCsvButton");
const measurementsLoading = document.getElementById("measurementsLoading");
const measurementsErrorBox = document.getElementById("measurementsErrorBox");
const measurementsSuccessBox = document.getElementById("measurementsSuccessBox");
const measurementStoredCount = document.getElementById("measurementStoredCount");
const measurementLoadedCount = document.getElementById("measurementLoadedCount");
const measurementPeriod = document.getElementById("measurementPeriod");
const measurementMin = document.getElementById("measurementMin");
const measurementAvg = document.getElementById("measurementAvg");
const measurementMax = document.getElementById("measurementMax");
const measurementChartWrap = document.getElementById("measurementChartWrap");
const measurementChart = document.getElementById("measurementChart");
const measurementTableBody = document.getElementById("measurementTableBody");


function currentDevice() {
    return devices.find(device => device.path === selectedDevicePath);
}


function clearInfoMessages() {
    infoErrorBox.style.display = "none";
    permissionBox.style.display = "none";
    infoSuccessBox.style.display = "none";
}


function clearConfigMessages() {
    configErrorBox.style.display = "none";
    configSuccessBox.style.display = "none";
    configWarningBox.style.display = "none";
}


function clearMeasurementMessages() {
    measurementsErrorBox.style.display = "none";
    measurementsSuccessBox.style.display = "none";
}


function resetMeasurementView() {
    measurementsLoaded = false;
    loadedMeasurementRecords = [];

    measurementStoredCount.textContent = "—";
    measurementLoadedCount.textContent = "—";
    measurementPeriod.textContent = "—";
    measurementMin.textContent = "—";
    measurementAvg.textContent = "—";
    measurementMax.textContent = "—";

    measurementChartWrap.style.display = "none";
    measurementChart.innerHTML = "";

    measurementTableBody.innerHTML = "";

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = 6;
    cell.className = "measurement-empty";
    cell.textContent = "Még nincs betöltött mérési adat.";

    row.appendChild(cell);
    measurementTableBody.appendChild(row);

    exportCsvButton.disabled = true;
}


function updateDeviceHeaders() {
    const device = currentDevice();

    if (!device) {
        infoEmptyState.style.display = "flex";
        infoContent.style.display = "none";
        configEmptyState.style.display = "flex";
        configContent.style.display = "none";
        measurementsEmptyState.style.display = "flex";
        measurementsContent.style.display = "none";
        return;
    }

    infoEmptyState.style.display = "none";
    infoContent.style.display = "block";

    configEmptyState.style.display = "none";
    configContent.style.display = "block";

    measurementsEmptyState.style.display = "none";
    measurementsContent.style.display = "block";

    selectedDeviceName.textContent = device.name || "Elitech RC-5";
    selectedDevicePathEl.textContent =
        device.path + " · " + device.vendor_id + ":" + device.product_id;

    configDeviceName.textContent = device.name || "Elitech RC-5";
    configDevicePath.textContent =
        device.path + " · " + device.vendor_id + ":" + device.product_id;

    measurementsDeviceName.textContent = device.name || "Elitech RC-5";
    measurementsDevicePath.textContent =
        device.path + " · " + device.vendor_id + ":" + device.product_id;
}


function selectDevice(path) {
    if (selectedDevicePath === path) {
        return;
    }

    selectedDevicePath = path;
    configLoaded = false;
    currentRecordCount = null;
    resetMeasurementView();

    renderDeviceList();
    updateDeviceHeaders();

    infoGrid.innerHTML = "";
    clearInfoMessages();
    clearConfigMessages();
    clearMeasurementMessages();

    if (!selectedDevicePath) {
        return;
    }

    if (activeTab === "info") {
        refreshDeviceInfo();
    } else if (activeTab === "config") {
        loadDeviceConfig();
    } else {
        loadDeviceMeasurements();
    }
}


function renderDeviceList() {
    deviceList.innerHTML = "";

    if (devices.length === 0) {
        const empty = document.createElement("div");
        empty.className = "device-list-empty";
        empty.textContent = "Nincs elérhető RC-5";
        deviceList.appendChild(empty);

        selectedDevicePath = "";
        deviceStatus.textContent = "Nincs csatlakoztatott RC-5.";
        deviceStatus.className = "device-status offline";

        updateDeviceHeaders();
        return;
    }

    for (const device of devices) {
        const item = document.createElement("button");
        item.type = "button";
        item.className =
            "device-item" +
            (device.path === selectedDevicePath ? " selected" : "");

        const name = document.createElement("span");
        name.className = "device-item-name";
        name.textContent = device.name || "Elitech RC-5";

        const meta = document.createElement("span");
        meta.className = "device-item-meta";
        meta.textContent =
            device.path + " · " + device.vendor_id + ":" + device.product_id;

        item.appendChild(name);
        item.appendChild(meta);

        item.addEventListener("click", () => {
            selectDevice(device.path);
        });

        deviceList.appendChild(item);
    }

    deviceStatus.textContent =
        devices.length + " kompatibilis eszköz csatlakoztatva.";
    deviceStatus.className = "device-status online";
}


async function refreshDevices() {
    try {
        const response = await fetch("/api/devices?t=" + Date.now());

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const oldSelection = selectedDevicePath;
        devices = await response.json();

        const stillExists = devices.some(
            device => device.path === oldSelection
        );

        if (!stillExists) {
            if (devices.length === 1) {
                selectedDevicePath = devices[0].path;
            } else {
                selectedDevicePath = "";
            }

            configLoaded = false;
            currentRecordCount = null;
            resetMeasurementView();
        }

        const selectionChanged = oldSelection !== selectedDevicePath;

        renderDeviceList();
        updateDeviceHeaders();

        if (selectionChanged && selectedDevicePath) {
            if (activeTab === "info") {
                refreshDeviceInfo();
            } else if (activeTab === "config") {
                loadDeviceConfig();
            } else {
                loadDeviceMeasurements();
            }
        }
    } catch (error) {
        deviceStatus.textContent = "A háttérfolyamat nem érhető el.";
        deviceStatus.className = "device-status offline";
    }
}


function renderInfoFields(fields) {
    infoGrid.innerHTML = "";

    for (const field of fields) {
        const item = document.createElement("div");
        item.className = "info-item";

        const label = document.createElement("div");
        label.className = "info-label";
        label.textContent = field.label;

        const value = document.createElement("div");
        value.className = "info-value";
        value.textContent = field.value;

        item.appendChild(label);
        item.appendChild(value);
        infoGrid.appendChild(item);
    }
}


async function refreshDeviceInfo() {
    if (!selectedDevicePath || infoBusy) {
        return;
    }

    infoBusy = true;
    const requestedPath = selectedDevicePath;

    infoLoading.style.display = "block";
    refreshInfoButton.disabled = true;
    clearInfoMessages();

    try {
        const response = await fetch(
            "/api/device-info?path=" +
            encodeURIComponent(requestedPath) +
            "&t=" +
            Date.now()
        );

        const data = await response.json();

        if (requestedPath !== selectedDevicePath) {
            return;
        }

        if (!response.ok) {
            if (
                response.status === 403 &&
                data.code === "permission_denied"
            ) {
                infoGrid.innerHTML = "";
                permissionBox.style.display = "block";
                return;
            }

            throw new Error(data.error || ("HTTP " + response.status));
        }

        renderInfoFields(data.fields);
    } catch (error) {
        if (requestedPath === selectedDevicePath) {
            infoGrid.innerHTML = "";
            infoErrorBox.textContent =
                "Nem sikerült kiolvasni az eszközt:\n" +
                error.message;
            infoErrorBox.style.display = "block";
        }
    } finally {
        if (requestedPath === selectedDevicePath) {
            infoLoading.style.display = "none";
            refreshInfoButton.disabled = false;
        }

        infoBusy = false;
    }
}


function updateConfigPreview() {
    const intervalMinutes = Number(sampleInterval.value);

    if (!Number.isFinite(intervalMinutes) || intervalMinutes <= 0) {
        recordsPerDay.textContent = "—";
        recordsPerYear.textContent = "—";
        memoryDuration.textContent = "—";
        return;
    }

    const perDay = 1440 / intervalMinutes;
    const perYear = perDay * 365;
    const yearsCapacity = currentCapacity / perYear;

    recordsPerDay.textContent =
        perDay.toLocaleString("hu-HU", { maximumFractionDigits: 2 });

    recordsPerYear.textContent =
        Math.ceil(perYear).toLocaleString("hu-HU");

    memoryDuration.textContent =
        yearsCapacity.toLocaleString(
            "hu-HU",
            {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            }
        ) + " év";
}



function showSafetyConfirm({
    title,
    message,
    okSide = "right",
    okLabel = "OK",
    cancelLabel = "Mégse",
    danger = false
}) {
    return new Promise(resolve => {
        let settled = false;

        safetyModalTitle.textContent = title;
        safetyModalBody.textContent = message;
        safetyModalActions.innerHTML = "";

        const cancelButton = document.createElement("button");
        cancelButton.type = "button";
        cancelButton.className = "safety-modal-button";
        cancelButton.textContent = cancelLabel;

        const okButton = document.createElement("button");
        okButton.type = "button";
        okButton.className =
            "safety-modal-button"
            + (danger ? " danger" : "");
        okButton.textContent = okLabel;

        const finish = value => {
            if (settled) {
                return;
            }

            settled = true;

            document.removeEventListener(
                "keydown",
                onKeyDown
            );

            safetyModalBackdrop.classList.remove(
                "open"
            );

            safetyModalBackdrop.setAttribute(
                "aria-hidden",
                "true"
            );

            safetyModalActions.innerHTML = "";

            resolve(value);
        };

        const onKeyDown = event => {
            if (event.key === "Escape") {
                event.preventDefault();
                finish(false);
            }

            // Szándékosan nincs Enter=OK gyorsbillentyű.
            // A jóváhagyáshoz tényleges kattintás kell.
        };

        cancelButton.addEventListener(
            "click",
            () => finish(false)
        );

        okButton.addEventListener(
            "click",
            () => finish(true)
        );

        if (okSide === "left") {
            safetyModalActions.appendChild(okButton);
            safetyModalActions.appendChild(cancelButton);
        } else {
            safetyModalActions.appendChild(cancelButton);
            safetyModalActions.appendChild(okButton);
        }

        safetyModalBackdrop.classList.add(
            "open"
        );

        safetyModalBackdrop.setAttribute(
            "aria-hidden",
            "false"
        );

        document.addEventListener(
            "keydown",
            onKeyDown
        );

        // Mindkét ablaknál a Mégse kap fókuszt.
        // Így véletlen Enter sem tud destruktív műveletet indítani.
        cancelButton.focus();
    });
}


function updateConfigSaveState() {
    const intervalMinutes = Number(sampleInterval.value);

    const intervalValid =
        Number.isInteger(intervalMinutes) &&
        intervalMinutes >= 1 &&
        intervalMinutes <= 1440;

    saveConfigButton.disabled =
        !configLoaded ||
        !intervalValid ||
        configBusy;
}


function renderConfig(data) {
    currentCapacity = data.capacity;
    currentRecordCount = data.record_count;

    const minutes = Number(data.interval_minutes);

    if (Number.isFinite(minutes)) {
        sampleInterval.value =
            Number.isInteger(minutes)
            ? String(minutes)
            : String(Math.round(minutes * 100) / 100);
    }

    allowButtonStop.checked = Boolean(data.button_stop);
    allowSoftwareStop.checked = Boolean(data.software_stop);

    currentDeviceTime.value = data.device_time || "—";

    configCapacity.textContent =
        (
            data.capacity === null
            || data.capacity === undefined
        )
        ? "-"
        : Number(data.capacity).toLocaleString("hu-HU") + " mérés";

    configRecordCount.textContent =
        (
            data.record_count === null
            || data.record_count === undefined
        )
        ? "-"
        : Number(data.record_count).toLocaleString("hu-HU");

    if (Number(data.record_count) === 0) {
        configAllowed.textContent = "Igen";
        configAllowed.className = "preview-value status-value-ok";
        configWarningBox.style.display = "none";
    } else {
        configAllowed.textContent = "Igen, kettős megerősítéssel";
        configAllowed.className = "preview-value status-value-blocked";

        configWarningBox.textContent = data.blocked_reason;
        configWarningBox.style.display = "block";
    }

    configLoaded = true;
    updateConfigPreview();
    updateConfigSaveState();
}


async function loadDeviceConfig() {
    if (!selectedDevicePath || configBusy) {
        return;
    }

    configBusy = true;
    configLoaded = false;

    const requestedPath = selectedDevicePath;

    configLoading.style.display = "block";
    reloadConfigButton.disabled = true;
    saveConfigButton.disabled = true;
    clearConfigMessages();

    try {
        const response = await fetch(
            "/api/device-config?path=" +
            encodeURIComponent(requestedPath) +
            "&t=" +
            Date.now()
        );

        const data = await response.json();

        if (requestedPath !== selectedDevicePath) {
            return;
        }

        if (!response.ok) {
            if (
                response.status === 403 &&
                data.code === "permission_denied"
            ) {
                throw new Error(
                    "Nincs jogosultság a HID eszköz konfigurációjának "
                    + "beolvasásához. Nyisd meg az Eszköz információk tabot "
                    + "és állítsd be az USB-jogosultságot."
                );
            }

            throw new Error(data.error || ("HTTP " + response.status));
        }

        renderConfig(data);
    } catch (error) {
        configErrorBox.textContent =
            "Nem sikerült beolvasni a konfigurációt:\n" +
            error.message;
        configErrorBox.style.display = "block";
    } finally {
        if (requestedPath === selectedDevicePath) {
            configLoading.style.display = "none";
            reloadConfigButton.disabled = false;
        }

        configBusy = false;
        updateConfigSaveState();
    }
}


async function saveDeviceConfig() {
    if (
        !selectedDevicePath
        || configBusy
        || !configLoaded
    ) {
        return;
    }

    const intervalMinutes = Number(
        sampleInterval.value
    );

    if (
        !Number.isInteger(intervalMinutes)
        || intervalMinutes < 1
        || intervalMinutes > 1440
    ) {
        configErrorBox.textContent =
            "A mintavételi időköz 1 és 1440 közötti egész perc legyen.";
        configErrorBox.style.display = "block";
        return;
    }

    const destructive =
        Number(currentRecordCount) > 0;

    const configSummary =
        `Mintavétel: ${intervalMinutes} perc
Indítás: kézi (▶ gomb)
Gombos leállítás: ${allowButtonStop.checked ? "engedélyezve" : "letiltva"}
Szoftveres leállítás: ${allowSoftwareStop.checked ? "engedélyezve" : "letiltva"}
Óraszinkron: ${syncClock.checked ? "igen" : "nem"}`;

    if (destructive) {
        const firstConfirmed =
            await showSafetyConfirm({
                title: "1/2 – A tárolt mérések törlődnek",
                message:
                    `A logger jelenleg ${Number(currentRecordCount).toLocaleString("hu-HU")} tárolt mérési rekordot tartalmaz.

A konfiguráció mentése a gyári FormatCommand műveletet használja, ezért a jelenlegi mérési adatok törlődnek.

Mielőtt folytatod, ellenőrizd, hogy a fontos méréseket már beolvastad és szükség esetén CSV-be exportáltad.

${configSummary}`,
                okSide: "left",
                okLabel: "OK",
                cancelLabel: "Mégse",
                danger: false
            });

        if (!firstConfirmed) {
            return;
        }

        const secondConfirmed =
            await showSafetyConfirm({
                title: "2/2 – Végleges jóváhagyás",
                message:
                    `Ez a második, végleges megerősítés.

A következő OK kattintás után a program elküldi a 6 SetParameter packetet és a FormatCommandot. A logger ${Number(currentRecordCount).toLocaleString("hu-HU")} jelenlegi rekordja várhatóan törlődik.

A mentés után a mérés NEM indul el automatikusan. A készüléket ezután a ▶ gomb hosszú nyomásával lehet új mérési ciklusra indítani.`,
                okSide: "right",
                okLabel: "OK",
                cancelLabel: "Mégse",
                danger: true
            });

        if (!secondConfirmed) {
            return;
        }
    } else {
        const confirmed =
            await showSafetyConfirm({
                title: "Konfiguráció mentése",
                message:
                    `${configSummary}

A mérés ettől nem indul el automatikusan.

A program az ElitechLog Win V8.0.5.0 visszafejtett gyári save-flow-ját használja.`,
                okSide: "right",
                okLabel: "OK",
                cancelLabel: "Mégse",
                danger: false
            });

        if (!confirmed) {
            return;
        }
    }

    configBusy = true;
    saveConfigButton.disabled = true;
    reloadConfigButton.disabled = true;
    clearConfigMessages();

    const requestedPath = selectedDevicePath;
    const confirmedRecordCount =
        Number(currentRecordCount);

    try {
        const response = await fetch(
            "/api/device-config",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Elitech-Token": APP_TOKEN
                },
                body: JSON.stringify({
                    path: requestedPath,
                    interval_minutes: intervalMinutes,
                    sync_clock: syncClock.checked,
                    button_stop: allowButtonStop.checked,
                    software_stop: allowSoftwareStop.checked,
                    allow_data_loss: destructive,
                    expected_record_count:
                        confirmedRecordCount
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error
                || ("HTTP " + response.status)
            );
        }

        configSuccessBox.textContent =
            (
                destructive
                ? `${confirmedRecordCount.toLocaleString("hu-HU")} korábbi rekord törlését jóváhagytad. `
                : ""
            )
            + data.message
            + " Készülékidő: "
            + data.device_time
            + " "
            + (data.persistence_note || "");

        configSuccessBox.style.display = "block";

        // Mentés után egyszer visszaolvassuk a teljes konfigurációt.
        configBusy = false;
        await loadDeviceConfig();

        // A sikerüzenetet a load ne takarja el.
        configSuccessBox.textContent =
            (
                destructive
                ? `${confirmedRecordCount.toLocaleString("hu-HU")} korábbi rekord törlését jóváhagytad. `
                : ""
            )
            + data.message
            + " Készülékidő: "
            + data.device_time
            + " "
            + (data.persistence_note || "");

        configSuccessBox.style.display = "block";

    } catch (error) {
        configErrorBox.textContent =
            "A konfiguráció mentése nem sikerült:\n"
            + error.message;
        configErrorBox.style.display = "block";
    } finally {
        configBusy = false;
        reloadConfigButton.disabled = false;
        updateConfigSaveState();
    }
}



function formatTemperature(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) {
        return "—";
    }

    return Number(value).toLocaleString(
        "hu-HU",
        {
            minimumFractionDigits: 1,
            maximumFractionDigits: 1
        }
    ) + " °C";
}


function formatHumidity(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) {
        return "-";
    }

    return Number(value).toLocaleString(
        "hu-HU",
        {
            minimumFractionDigits: 1,
            maximumFractionDigits: 1
        }
    ) + " %";
}


function renderMeasurementTable(records) {
    measurementTableBody.innerHTML = "";

    if (records.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.className = "measurement-empty";
        cell.textContent = "A loggerben nincs megjeleníthető mérési rekord.";

        row.appendChild(cell);
        measurementTableBody.appendChild(row);
        return;
    }

    for (const record of records) {
        const row = document.createElement("tr");

        if (record.status === "Értelmezési hiba") {
            row.className = "error-row";
        } else if (record.status !== "Mérés") {
            row.className = "event-row";
        }

        const values = [
            record.index,
            record.timestamp || "—",
            formatTemperature(record.temperature),
            formatHumidity(record.humidity),
            record.status || "—",
            (
                Array.isArray(record.flags) && record.flags.length
                ? record.flags.join(", ")
                : "—"
            )
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = String(value);

            if (index === 0 || index === 2 || index === 3) {
                cell.className = "numeric";
            }

            if (
                record.status === "Értelmezési hiba"
                && index === 5
                && record.raw_hex
            ) {
                cell.textContent =
                    "raw: " + record.raw_hex;
                cell.title = record.parse_error || "";
            }

            row.appendChild(cell);
        });

        measurementTableBody.appendChild(row);
    }
}


function parseMeasurementTimestamp(timestamp) {
    const match = String(timestamp || "").match(
        /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/
    );

    if (!match) {
        return NaN;
    }

    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);

    return new Date(
        year,
        month - 1,
        day,
        hour,
        minute,
        second
    ).getTime();
}


function formatChartAxisLabel(timeMs, spanMs) {
    const date = new Date(timeMs);

    if (spanMs <= 36 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "hu-HU",
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 10 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "hu-HU",
            {
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 90 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "hu-HU",
            {
                month: "short",
                day: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 550 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "hu-HU",
            {
                year: "numeric",
                month: "short"
            }
        ).format(date);
    }

    return new Intl.DateTimeFormat(
        "hu-HU",
        {
            year: "numeric"
        }
    ).format(date);
}


function formatChartTooltipTime(timeMs) {
    return new Intl.DateTimeFormat(
        "hu-HU",
        {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    ).format(new Date(timeMs));
}


function findNearestMeasurementByTime(points, targetTime) {
    if (points.length === 0) {
        return null;
    }

    let low = 0;
    let high = points.length - 1;

    while (low < high) {
        const middle = Math.floor(
            (low + high) / 2
        );

        if (points[middle].time < targetTime) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if (low === 0) {
        return points[0];
    }

    const current = points[low];
    const previous = points[low - 1];

    return (
        Math.abs(current.time - targetTime)
        < Math.abs(previous.time - targetTime)
        ? current
        : previous
    );
}


function renderMeasurementChart(records) {
    const chartData = records
        .filter(
            record =>
                record.status === "Mérés"
                && record.timestamp
                && record.temperature !== null
                && Number.isFinite(Number(record.temperature))
        )
        .map(
            record => ({
                ...record,
                time: parseMeasurementTimestamp(record.timestamp),
                temperatureNumber: Number(record.temperature)
            })
        )
        .filter(
            record => Number.isFinite(record.time)
        )
        .sort(
            (a, b) => a.time - b.time
        );

    if (chartData.length < 2) {
        measurementChartWrap.style.display = "none";
        measurementChart.innerHTML = "";
        return;
    }

    const minTime = chartData[0].time;
    const maxTime = chartData[chartData.length - 1].time;
    const timeSpan = Math.max(1, maxTime - minTime);

    const temperatures = chartData.map(
        record => record.temperatureNumber
    );

    let minTemp = Math.min(...temperatures);
    let maxTemp = Math.max(...temperatures);

    if (minTemp === maxTemp) {
        minTemp -= 0.5;
        maxTemp += 0.5;
    }

    const maxPolylinePoints = 1500;
    const stride = Math.max(
        1,
        Math.ceil(chartData.length / maxPolylinePoints)
    );

    const lineData = chartData.filter(
        (_, index) =>
            index % stride === 0
            || index === chartData.length - 1
    );

    const width = 1000;
    const height = 300;
    const left = 68;
    const right = 22;
    const top = 18;
    const bottom = 62;

    const plotWidth = width - left - right;
    const plotHeight = height - top - bottom;

    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute(
        "aria-label",
        "Interaktív hőmérséklet-idősor"
    );

    const xForTime = time =>
        left
        + ((time - minTime) / timeSpan) * plotWidth;

    const yForTemperature = temperature =>
        top
        + (
            (maxTemp - temperature)
            / (maxTemp - minTemp)
        ) * plotHeight;

    const addLine = (
        x1,
        y1,
        x2,
        y2,
        stroke,
        dash = "",
        widthValue = "1"
    ) => {
        const line = document.createElementNS(ns, "line");
        line.setAttribute("x1", x1);
        line.setAttribute("y1", y1);
        line.setAttribute("x2", x2);
        line.setAttribute("y2", y2);
        line.setAttribute("stroke", stroke);
        line.setAttribute("stroke-width", widthValue);

        if (dash) {
            line.setAttribute("stroke-dasharray", dash);
        }

        svg.appendChild(line);
        return line;
    };

    const addText = (
        x,
        y,
        value,
        anchor = "start",
        fontSize = "12"
    ) => {
        const node = document.createElementNS(ns, "text");
        node.setAttribute("x", x);
        node.setAttribute("y", y);
        node.setAttribute("text-anchor", anchor);
        node.setAttribute("font-size", fontSize);
        node.setAttribute("fill", "#5e6673");
        node.textContent = value;
        svg.appendChild(node);
        return node;
    };

    // Y grid + labels.
    for (let gridIndex = 0; gridIndex <= 4; gridIndex++) {
        const ratio = gridIndex / 4;
        const y = top + ratio * plotHeight;
        const value =
            maxTemp - ratio * (maxTemp - minTemp);

        addLine(
            left,
            y,
            width - right,
            y,
            "#e2e6eb"
        );

        addText(
            left - 9,
            y + 4,
            value.toLocaleString(
                "hu-HU",
                {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1
                }
            ) + " °C",
            "end"
        );
    }

    // Adaptive X axis.
    const tickCount = 7;

    for (let tickIndex = 0; tickIndex < tickCount; tickIndex++) {
        const ratio =
            tickIndex / (tickCount - 1);

        const tickTime =
            minTime + ratio * timeSpan;

        const x =
            left + ratio * plotWidth;

        addLine(
            x,
            top,
            x,
            top + plotHeight,
            "#eef0f3",
            "3 5"
        );

        addText(
            x,
            height - 22,
            formatChartAxisLabel(
                tickTime,
                timeSpan
            ),
            (
                tickIndex === 0
                ? "start"
                : (
                    tickIndex === tickCount - 1
                    ? "end"
                    : "middle"
                )
            ),
            "11"
        );
    }

    // Temperature line.
    const polyline = document.createElementNS(ns, "polyline");

    polyline.setAttribute(
        "points",
        lineData
            .map(
                record =>
                    `${xForTime(record.time).toFixed(2)},${yForTemperature(record.temperatureNumber).toFixed(2)}`
            )
            .join(" ")
    );

    polyline.setAttribute("fill", "none");
    polyline.setAttribute("stroke", "#2457d6");
    polyline.setAttribute("stroke-width", "2");
    polyline.setAttribute(
        "vector-effect",
        "non-scaling-stroke"
    );

    svg.appendChild(polyline);

    // Hover line.
    const hoverLine = document.createElementNS(ns, "line");
    hoverLine.setAttribute("stroke", "#5d6570");
    hoverLine.setAttribute("stroke-width", "1");
    hoverLine.setAttribute("stroke-dasharray", "4 4");
    hoverLine.style.display = "none";
    svg.appendChild(hoverLine);

    // Hover point.
    const hoverCircle = document.createElementNS(ns, "circle");
    hoverCircle.setAttribute("r", "5");
    hoverCircle.setAttribute("fill", "#2457d6");
    hoverCircle.setAttribute("stroke", "#ffffff");
    hoverCircle.setAttribute("stroke-width", "2");
    hoverCircle.style.display = "none";
    svg.appendChild(hoverCircle);

    // Tooltip.
    const tooltipGroup = document.createElementNS(ns, "g");
    tooltipGroup.style.display = "none";
    tooltipGroup.style.pointerEvents = "none";

    const tooltipRect = document.createElementNS(ns, "rect");
    tooltipRect.setAttribute("width", "210");
    tooltipRect.setAttribute("height", "70");
    tooltipRect.setAttribute("rx", "6");
    tooltipRect.setAttribute("fill", "#ffffff");
    tooltipRect.setAttribute("stroke", "#b9c0c9");
    tooltipGroup.appendChild(tooltipRect);

    const tooltipTime = document.createElementNS(ns, "text");
    tooltipTime.setAttribute("x", "10");
    tooltipTime.setAttribute("y", "20");
    tooltipTime.setAttribute("font-size", "12");
    tooltipTime.setAttribute("fill", "#3d4652");
    tooltipGroup.appendChild(tooltipTime);

    const tooltipTemperature = document.createElementNS(ns, "text");
    tooltipTemperature.setAttribute("x", "10");
    tooltipTemperature.setAttribute("y", "41");
    tooltipTemperature.setAttribute("font-size", "14");
    tooltipTemperature.setAttribute("font-weight", "700");
    tooltipTemperature.setAttribute("fill", "#2457d6");
    tooltipGroup.appendChild(tooltipTemperature);

    const tooltipIndex = document.createElementNS(ns, "text");
    tooltipIndex.setAttribute("x", "10");
    tooltipIndex.setAttribute("y", "60");
    tooltipIndex.setAttribute("font-size", "11");
    tooltipIndex.setAttribute("fill", "#69717c");
    tooltipGroup.appendChild(tooltipIndex);

    svg.appendChild(tooltipGroup);

    // Transparent interaction layer over the plot.
    const hoverOverlay = document.createElementNS(ns, "rect");
    hoverOverlay.setAttribute("x", left);
    hoverOverlay.setAttribute("y", top);
    hoverOverlay.setAttribute("width", plotWidth);
    hoverOverlay.setAttribute("height", plotHeight);
    hoverOverlay.setAttribute("fill", "transparent");
    hoverOverlay.style.pointerEvents = "all";

    hoverOverlay.addEventListener(
        "mousemove",
        event => {
            const bounds = svg.getBoundingClientRect();

            const mouseX =
                ((event.clientX - bounds.left) / bounds.width)
                * width;

            const clampedX = Math.max(
                left,
                Math.min(width - right, mouseX)
            );

            const targetTime =
                minTime
                + ((clampedX - left) / plotWidth) * timeSpan;

            const nearest =
                findNearestMeasurementByTime(
                    chartData,
                    targetTime
                );

            if (!nearest) {
                return;
            }

            const pointX = xForTime(nearest.time);
            const pointY =
                yForTemperature(nearest.temperatureNumber);

            hoverLine.setAttribute("x1", pointX);
            hoverLine.setAttribute("x2", pointX);
            hoverLine.setAttribute("y1", top);
            hoverLine.setAttribute("y2", top + plotHeight);
            hoverLine.style.display = "";

            hoverCircle.setAttribute("cx", pointX);
            hoverCircle.setAttribute("cy", pointY);
            hoverCircle.style.display = "";

            tooltipTime.textContent =
                formatChartTooltipTime(nearest.time);

            tooltipTemperature.textContent =
                formatTemperature(
                    nearest.temperatureNumber
                );

            tooltipIndex.textContent =
                "Mérés #" + nearest.index;

            const tooltipWidth = 210;
            const tooltipHeight = 70;

            let tooltipX = pointX + 12;

            if (
                tooltipX + tooltipWidth
                > width - right
            ) {
                tooltipX =
                    pointX - tooltipWidth - 12;
            }

            let tooltipY =
                pointY - tooltipHeight - 10;

            if (tooltipY < top) {
                tooltipY = pointY + 12;
            }

            tooltipGroup.setAttribute(
                "transform",
                `translate(${tooltipX}, ${tooltipY})`
            );

            tooltipGroup.style.display = "";
        }
    );

    hoverOverlay.addEventListener(
        "mouseleave",
        () => {
            hoverLine.style.display = "none";
            hoverCircle.style.display = "none";
            tooltipGroup.style.display = "none";
        }
    );

    svg.appendChild(hoverOverlay);

    measurementChart.replaceChildren(svg);
    measurementChartWrap.style.display = "block";
}


function renderMeasurementSummary(data) {
    const records = data.records || [];

    measurementStoredCount.textContent =
        Number(data.stored_count || 0).toLocaleString("hu-HU");

    measurementLoadedCount.textContent =
        Number(data.loaded_count || 0).toLocaleString("hu-HU");

    const timedRecords = records.filter(
        record => Boolean(record.timestamp)
    );

    if (timedRecords.length > 0) {
        measurementPeriod.textContent =
            timedRecords[0].timestamp
            + " → "
            + timedRecords[timedRecords.length - 1].timestamp;
    } else {
        measurementPeriod.textContent = "—";
    }

    const temperatures = records
        .filter(
            record =>
                record.status === "Mérés"
                && record.temperature !== null
                && Number.isFinite(Number(record.temperature))
        )
        .map(
            record => Number(record.temperature)
        );

    if (temperatures.length === 0) {
        measurementMin.textContent = "—";
        measurementAvg.textContent = "—";
        measurementMax.textContent = "—";
        return;
    }

    const minimum = Math.min(...temperatures);
    const maximum = Math.max(...temperatures);
    const average =
        temperatures.reduce((sum, value) => sum + value, 0)
        / temperatures.length;

    measurementMin.textContent = formatTemperature(minimum);
    measurementAvg.textContent = formatTemperature(average);
    measurementMax.textContent = formatTemperature(maximum);
}


function renderMeasurements(data) {
    loadedMeasurementRecords = Array.isArray(data.records)
        ? data.records
        : [];

    measurementsLoaded = true;

    renderMeasurementSummary(data);
    renderMeasurementTable(loadedMeasurementRecords);
    renderMeasurementChart(loadedMeasurementRecords);

    exportCsvButton.disabled =
        loadedMeasurementRecords.length === 0;
}


async function loadDeviceMeasurements() {
    if (!selectedDevicePath || measurementsBusy) {
        return;
    }

    measurementsBusy = true;
    clearMeasurementMessages();

    const requestedPath = selectedDevicePath;
    const limit = Number(measurementLimit.value);

    measurementsLoading.style.display = "block";
    reloadMeasurementsButton.disabled = true;
    exportCsvButton.disabled = true;

    try {
        const response = await fetch(
            "/api/device-records?path="
            + encodeURIComponent(requestedPath)
            + "&limit="
            + encodeURIComponent(String(limit))
            + "&t="
            + Date.now()
        );

        const data = await response.json();

        if (requestedPath !== selectedDevicePath) {
            return;
        }

        if (!response.ok) {
            if (
                response.status === 403
                && data.code === "permission_denied"
            ) {
                throw new Error(
                    "Nincs jogosultság a HID eszköz rekordjainak "
                    + "beolvasásához. Nyisd meg az Eszköz információk "
                    + "tabot és állítsd be az USB-jogosultságot."
                );
            }

            throw new Error(
                data.error || ("HTTP " + response.status)
            );
        }

        renderMeasurements(data);

        if (Number(data.stored_count) === 0) {
            measurementsSuccessBox.textContent =
                "A logger jelenleg nem tartalmaz mérési rekordot.";
        } else if (
            Number(data.loaded_count)
            < Number(data.stored_count)
        ) {
            measurementsSuccessBox.textContent =
                data.loaded_count.toLocaleString("hu-HU")
                + " rekord betöltve a tárolt "
                + data.stored_count.toLocaleString("hu-HU")
                + " rekordból.";
        } else {
            measurementsSuccessBox.textContent =
                data.loaded_count.toLocaleString("hu-HU")
                + " mérési rekord betöltve.";
        }

        measurementsSuccessBox.style.display = "block";

    } catch (error) {
        measurementsErrorBox.textContent =
            "A mérési rekordok beolvasása nem sikerült:\n"
            + error.message;
        measurementsErrorBox.style.display = "block";
    } finally {
        if (requestedPath === selectedDevicePath) {
            measurementsLoading.style.display = "none";
            reloadMeasurementsButton.disabled = false;
            exportCsvButton.disabled =
                !measurementsLoaded
                || loadedMeasurementRecords.length === 0;
        }

        measurementsBusy = false;
    }
}


function csvEscape(value) {
    const text = String(
        value === null || value === undefined
        ? ""
        : value
    );

    if (
        text.includes(";")
        || text.includes('"')
        || text.includes("\n")
        || text.includes("\r")
    ) {
        return '"'
            + text.replaceAll('"', '""')
            + '"';
    }

    return text;
}


function exportMeasurementsCsv() {
    if (loadedMeasurementRecords.length === 0) {
        return;
    }

    const rows = [
        [
            "Sorszám",
            "Időpont",
            "Hőmérséklet (°C)",
            "Páratartalom (%)",
            "Állapot",
            "Jelzők",
            "Nyers rekord"
        ]
    ];

    for (const record of loadedMeasurementRecords) {
        rows.push(
            [
                record.index,
                record.timestamp || "",
                (
                    record.temperature === null
                    || record.temperature === undefined
                    ? ""
                    : Number(record.temperature).toFixed(1)
                ),
                (
                    record.humidity === null
                    || record.humidity === undefined
                    ? ""
                    : Number(record.humidity).toFixed(1)
                ),
                record.status || "",
                (
                    Array.isArray(record.flags)
                    ? record.flags.join(", ")
                    : ""
                ),
                record.raw_hex || ""
            ]
        );
    }

    const csv =
        "\uFEFF"
        + rows
            .map(
                row =>
                    row
                        .map(csvEscape)
                        .join(";")
            )
            .join("\r\n");

    const blob = new Blob(
        [csv],
        {
            type: "text/csv;charset=utf-8"
        }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    const now = new Date();
    const datePart =
        now.getFullYear()
        + "-"
        + String(now.getMonth() + 1).padStart(2, "0")
        + "-"
        + String(now.getDate()).padStart(2, "0");

    link.href = url;
    link.download =
        "elitech-rc5-meresek-"
        + datePart
        + ".csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}


async function installPermissionRule() {
    if (permissionBusy) {
        return;
    }

    permissionBusy = true;
    permissionButton.disabled = true;

    try {
        const response = await fetch(
            "/api/install-udev",
            {
                method: "POST",
                headers: {
                    "X-Elitech-Token": APP_TOKEN
                }
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || ("HTTP " + response.status));
        }

        infoSuccessBox.textContent = data.message;
        infoSuccessBox.style.display = "block";

        await new Promise(resolve => setTimeout(resolve, 700));
        await refreshDevices();

        if (activeTab === "info") {
            await refreshDeviceInfo();
        }
    } catch (error) {
        infoErrorBox.textContent =
            "A jogosultság beállítása nem sikerült:\n"
            + error.message;
        infoErrorBox.style.display = "block";
    } finally {
        permissionBusy = false;
        permissionButton.disabled = false;
    }
}


function openTab(tabName) {
    activeTab = tabName;

    const infoActive = tabName === "info";
    const configActive = tabName === "config";
    const measurementsActive = tabName === "measurements";

    infoTabButton.classList.toggle(
        "active",
        infoActive
    );

    configTabButton.classList.toggle(
        "active",
        configActive
    );

    measurementsTabButton.classList.toggle(
        "active",
        measurementsActive
    );

    infoTabPage.classList.toggle(
        "active",
        infoActive
    );

    configTabPage.classList.toggle(
        "active",
        configActive
    );

    measurementsTabPage.classList.toggle(
        "active",
        measurementsActive
    );

    updateDeviceHeaders();

    if (!selectedDevicePath) {
        return;
    }

    // Csak a kiválasztott tab adatait olvassuk.
    // Nincs periodikus HID rekord/config/információ frissítés.
    if (infoActive) {
        refreshDeviceInfo();
    } else if (configActive) {
        loadDeviceConfig();
    } else if (measurementsActive) {
        loadDeviceMeasurements();
    }
}


function updateComputerTime() {
    computerTime.value =
        new Intl.DateTimeFormat(
            "hu-HU",
            {
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        ).format(new Date());
}


infoTabButton.addEventListener(
    "click",
    () => openTab("info")
);

configTabButton.addEventListener(
    "click",
    () => openTab("config")
);

measurementsTabButton.addEventListener(
    "click",
    () => openTab("measurements")
);

refreshInfoButton.addEventListener(
    "click",
    refreshDeviceInfo
);

reloadConfigButton.addEventListener(
    "click",
    loadDeviceConfig
);

saveConfigButton.addEventListener(
    "click",
    saveDeviceConfig
);

reloadMeasurementsButton.addEventListener(
    "click",
    loadDeviceMeasurements
);

exportCsvButton.addEventListener(
    "click",
    exportMeasurementsCsv
);

permissionButton.addEventListener(
    "click",
    installPermissionRule
);

sampleInterval.addEventListener(
    "input",
    () => {
        updateConfigPreview();
        updateConfigSaveState();
    }
);


async function start() {
    updateComputerTime();
    updateConfigPreview();

    // Ez csak a helyi számítógép kijelzett óráját frissíti.
    setInterval(updateComputerTime, 1000);

    await refreshDevices();

    // Csak az eszközlista frissül automatikusan.
    // A HID-adatok csak tab megnyitáskor vagy gombnyomásra frissülnek.
    setInterval(refreshDevices, 1000);
}


start();
</script>
</body>
</html>
"""


# ============================================================
# HTTP szerver
# ============================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        html = html.replace("__APP_TOKEN__", APP_TOKEN)
        body = html.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        content_length = self.headers.get("Content-Length", "0")

        try:
            length = int(content_length)
        except ValueError:
            raise ValueError("Érvénytelen Content-Length.")

        if length < 0 or length > 64 * 1024:
            raise ValueError("Érvénytelen kérésméret.")

        raw = self.rfile.read(length)

        if not raw:
            return {}

        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Érvénytelen JSON kérés.")

    def require_write_token(self):
        token = self.headers.get("X-Elitech-Token", "")

        if token != APP_TOKEN:
            self.send_json(
                {"error": "Érvénytelen vagy hiányzó alkalmazástoken."},
                status=403,
            )
            return False

        return True

    def resolve_device_or_404(self, device_path):
        device = find_device(device_path)

        if device is None:
            self.send_json(
                {
                    "error": (
                        "A kiválasztott RC-5 már nincs csatlakoztatva."
                    )
                },
                status=404,
            )
            return None

        return device

    def send_device_exception(self, error):
        LOGGER.exception(
            "REQUEST ERROR | %s: %s",
            type(error).__name__,
            error,
        )

        if isinstance(error, PermissionError):
            self.send_json(
                {
                    "code": "permission_denied",
                    "error": "Nincs jogosultság a HID eszköz megnyitásához.",
                },
                status=403,
            )
            return

        if isinstance(error, TimeoutError):
            self.send_json(
                {"error": str(error)},
                status=504,
            )
            return

        if isinstance(error, ValueError):
            self.send_json(
                {"error": str(error)},
                status=400,
            )
            return

        self.send_json(
            {"error": str(error)},
            status=500,
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_html(HTML)
            return

        if path == "/api/devices":
            self.send_json(scan_devices())
            return

        if path == "/api/device-info":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                info = read_device_info(device_path)
                info["device"] = device
                self.send_json(info)
            except (
                PermissionError,
                TimeoutError,
                OSError,
                ValueError,
                RuntimeError,
            ) as error:
                self.send_device_exception(error)

            return

        if path == "/api/device-records":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            try:
                limit = int(
                    query.get("limit", ["500"])[0]
                )
            except ValueError:
                self.send_json(
                    {"error": "Érvénytelen rekordlimit."},
                    status=400,
                )
                return

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                data = read_device_records(
                    device_path,
                    limit=limit,
                )
                data["device"] = device
                self.send_json(data)
            except Exception as error:
                self.send_device_exception(error)

            return

        if path == "/api/device-config":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                config = read_device_config(device_path)
                config["device"] = device
                self.send_json(config)
            except Exception as error:
                self.send_device_exception(error)

            return

        self.send_json(
            {"error": "Not found"},
            status=404,
        )

    def do_POST(self):
        parsed = urlparse(self.path)

        if not self.require_write_token():
            return

        if parsed.path == "/api/install-udev":
            try:
                result = install_udev_rule()
                self.send_json(result)
            except (
                RuntimeError,
                subprocess.SubprocessError,
                OSError,
            ) as error:
                self.send_json(
                    {"error": str(error)},
                    status=500,
                )
            return

        if parsed.path == "/api/device-config":
            try:
                payload = self.read_json_body()

                device_path = str(
                    payload.get("path", "")
                )

                device = self.resolve_device_or_404(device_path)
                if device is None:
                    return

                result = apply_device_config(
                    device_path,
                    interval_minutes=payload.get("interval_minutes"),
                    sync_clock=bool(payload.get("sync_clock", True)),
                    button_stop=bool(payload.get("button_stop", False)),
                    software_stop=bool(
                        payload.get("software_stop", False)
                    ),
                    allow_data_loss=bool(
                        payload.get("allow_data_loss", False)
                    ),
                    expected_record_count=payload.get(
                        "expected_record_count"
                    ),
                )

                self.send_json(result)

            except Exception as error:
                self.send_device_exception(error)

            return

        self.send_json(
            {"error": "Not found"},
            status=404,
        )


# ============================================================
# Böngészőindítás
# ============================================================

def open_browser():
    time.sleep(0.8)

    url = f"http://{HOST}:{PORT}/"
    firefox = shutil.which("firefox")

    if firefox:
        try:
            subprocess.Popen(
                [firefox, "--new-tab", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except OSError:
            pass

    try:
        webbrowser.open(url)
    except Exception:
        pass


# ============================================================
# Main
# ============================================================

def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}/"

    print()
    print(f"Elitech RC-5 Manager | {APP_VERSION}")
    print("---------------------------------------------")
    print(f"Web UI: {url}")
    print(f"Debug log: {DEBUG_LOG_PATH}")
    print("Leállítás: Ctrl+C")

    LOGGER.info(
        "APPLICATION START | version=%s | script=%s | url=%s | debug_log=%s",
        APP_VERSION,
        Path(__file__).name,
        url,
        DEBUG_LOG_PATH,
    )
    print()

    threading.Thread(
        target=open_browser,
        daemon=True,
    ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLeállítás...")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

