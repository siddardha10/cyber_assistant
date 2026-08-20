"""
monitors/usb.py

Windows-only. Uses the `wmi` package (wraps WMI over pywin32) to watch for
Win32_PnPEntity creation/deletion events in real time — this is the correct
Windows equivalent of the Linux pyudev approach mentioned in the original
project brief (pyudev does not exist on Windows, so that part of the brief
was corrected here).

Falls back to a polling diff (every INTERVAL_USB_POLL seconds) if the WMI
event watcher can't be set up (e.g. missing permissions), so the monitor
still produces useful data rather than doing nothing.
"""

import threading

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.usb")

try:
    import wmi  # requires: pip install wmi pywin32   (Windows only)
    _WMI_AVAILABLE = True
except ImportError:
    _WMI_AVAILABLE = False


def _extract_ids(pnp_device_id: str):
    """PNPDeviceID looks like USB\\VID_1234&PID_5678\\SERIAL"""
    vendor_id = product_id = None
    try:
        parts = pnp_device_id.split("\\")
        if len(parts) >= 2 and "VID_" in parts[1]:
            segs = parts[1].split("&")
            for s in segs:
                if s.startswith("VID_"):
                    vendor_id = s.replace("VID_", "")
                if s.startswith("PID_"):
                    product_id = s.replace("PID_", "")
    except Exception:
        pass
    return vendor_id, product_id


def _log_event(device_name, pnp_id, action):
    vendor_id, product_id = _extract_ids(pnp_id or "")
    serial = pnp_id.split("\\")[-1] if pnp_id else None
    db.insert("usb_events", {
        "timestamp": db.now_iso(),
        "device_name": device_name,
        "vendor_id": vendor_id,
        "product_id": product_id,
        "serial_number": serial,
        "drive_letter": None,
        "action": action,
    })
    if action == "inserted":
        log.info("USB inserted: %s", device_name)


def _run_wmi_watcher(stop_event: threading.Event):
    c = wmi.WMI()
    insert_watcher = c.watch_for(
        notification_type="Creation", wmi_class="Win32_PnPEntity", delay_secs=2
    )
    removal_watcher = c.watch_for(
        notification_type="Deletion", wmi_class="Win32_PnPEntity", delay_secs=2
    )

    def watch_loop(watcher, action):
        while not stop_event.is_set():
            try:
                event = watcher(timeout_ms=2000)
                if event and "USB" in (event.PNPDeviceID or "").upper():
                    _log_event(event.Name, event.PNPDeviceID, action)
            except wmi.x_wmi_timed_out:
                continue
            except Exception:
                log.exception("USB WMI watcher error (%s)", action)
                stop_event.wait(2)

    t1 = threading.Thread(target=watch_loop, args=(insert_watcher, "inserted"), daemon=True)
    t2 = threading.Thread(target=watch_loop, args=(removal_watcher, "removed"), daemon=True)
    t1.start()
    t2.start()
    while not stop_event.is_set():
        stop_event.wait(1)


def _run_polling_fallback(stop_event: threading.Event):
    c = wmi.WMI()
    previous = set()
    while not stop_event.is_set():
        try:
            current = set()
            for dev in c.Win32_PnPEntity(PNPClass="USB"):
                current.add((dev.Name, dev.PNPDeviceID))
            for name, pnp_id in current - previous:
                _log_event(name, pnp_id, "inserted")
            for name, pnp_id in previous - current:
                _log_event(name, pnp_id, "removed")
            previous = current
        except Exception:
            log.exception("USB polling cycle failed — continuing")
        stop_event.wait(config.INTERVAL_USB_POLL)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS:
        log.info("USB monitor skipped — not running on Windows")
        return
    if not _WMI_AVAILABLE:
        log.warning("USB monitor disabled: `pip install wmi pywin32` to enable it")
        return

    log.info("USB monitor started")
    try:
        _run_wmi_watcher(stop_event)
    except Exception:
        log.exception("WMI event watcher failed, falling back to polling")
        _run_polling_fallback(stop_event)
