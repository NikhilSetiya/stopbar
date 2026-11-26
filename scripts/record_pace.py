"""Pace quickstart.sh's output for the recording (scripts/record_quickstart.sh):
every line is printed as it arrives, held briefly so a viewer can read it, and
longer at each README step. Nothing is changed or dropped except the trailer
after the README block (the SDK-example check), which isn't part of the demo."""
import sys, time

done = False
for line in sys.stdin:
    if done:
        continue
    sys.stdout.write(line)
    time.sleep(1.2 if line.startswith("# ") else 0.02)
    done = line.startswith("ok   README quickstart")
time.sleep(2)
