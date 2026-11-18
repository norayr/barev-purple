#!/usr/bin/env python3
"""Compare pinned STARTTLS/SASL sequencing with an independent event model."""
from pathlib import Path
import subprocess
import sys

TOOLS = [Path(arg).resolve() for arg in sys.argv[1:]]
STREAM = "http://etherx.jabber.org/streams"
TLS = "urn:ietf:params:xml:ns:xmpp-tls"
SASL = "urn:ietf:params:xml:ns:xmpp-sasl"
TLS_FEATURES = f"<stream:features><starttls xmlns='{TLS}'><required/></starttls></stream:features>"
START = f"<starttls xmlns='{TLS}'/>"
PROCEED = f"<proceed xmlns='{TLS}'/>"
EX_FEATURES = f"<stream:features><mechanisms xmlns='{SASL}'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>"
EXTERNAL = f"<auth xmlns='{SASL}' mechanism='EXTERNAL'>=</auth>"
SUCCESS = f"<success xmlns='{SASL}'/>"
FINAL = "<stream:features/>"
OUTPUTS = {1: TLS_FEATURES, 2: START, 3: PROCEED, 6: EX_FEATURES, 7: EXTERNAL, 8: SUCCESS, 10: FINAL}
TRACES = {
    "client": [("open", 0), (TLS_FEATURES, 2), ("sent", 0), (PROCEED, 4), ("secure", 5),
               ("open", 0), (EX_FEATURES, 7), ("sent", 0), (SUCCESS, 9), ("open", 0), (FINAL, 11)],
    "server": [("open", 1), ("sent", 0), (START, 3), ("sent", 4), ("secure", 5),
               ("open", 6), ("sent", 0), (EXTERNAL, 8), ("sent", 9), ("open", 10), ("sent", 11)],
}


def run(tool, role, events):
    result = subprocess.run([str(tool), role, *events], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, (tool, role, events, result.returncode, result.stdout, result.stderr)
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split(" ", 4)
        assert len(fields) == 5, (tool, line)
        rows.append((*(int(field) for field in fields[:4]), fields[4]))
    assert len(rows) == len(events), (tool, events, rows)
    return rows


checks = 0
for tool in TOOLS:
    for role, trace in TRACES.items():
        events = [event for event, _ in trace]
        rows = run(tool, role, events)
        for index, (row, (_, action)) in enumerate(zip(rows, trace)):
            assert row == (action, int(action == 11), int(index == 3), int(action in OUTPUTS), OUTPUTS.get(action, "")), (tool, role, index, row)
            checks += 1
        for prefix in range(len(trace)+1):
            next_event = trace[prefix][0] if prefix < len(trace) else None
            invalid = ["open", "sent", "secure", "bad-tls", TLS_FEATURES, START, PROCEED, EX_FEATURES, EXTERNAL, SUCCESS, FINAL,
                       "<message xmlns='jabber:client'><body>early</body></message>",
                       f"<proceed xmlns='{TLS}'><extra/></proceed>",
                       "<proceed xmlns='jabber:client'/>",
                       f"<auth xmlns='{SASL}' mechanism='PLAIN'>=</auth>",
                       f"<auth xmlns='{SASL}' mechanism='EXTERNAL'>Ym9iQDIwMDo6Mg==</auth>",
                       f"<auth xmlns='{SASL}' mechanism='EXTERNAL'><child/></auth>",
                       f"<auth xmlns='{SASL}' mechanism='EXTERNAL' extra='x'>=</auth>",
                       f"<success xmlns='{SASL}'>data</success>",
                       f"<stream:features><starttls xmlns='{TLS}'/></stream:features>",
                       f"<stream:features><starttls xmlns='{TLS}'><required/><required/></starttls></stream:features>",
                       f"<stream:features><mechanisms xmlns='{SASL}'><mechanism>PLAIN</mechanism></mechanisms></stream:features>"]
            for event in invalid:
                if event == next_event:
                    continue
                rows = run(tool, role, events[:prefix]+[event, "open", "sent", "secure"])
                assert all(row == (-1, 0, 0, 0, "") for row in rows[prefix:]), (tool, role, prefix, event, rows)
                checks += 1
    print(tool.name+": STARTTLS/SASL ordering and application gate passed", flush=True)
assert TOOLS, "pass at least one authentication test executable"
print(f"Authenticated stream sequencing: {checks} checks passed")
