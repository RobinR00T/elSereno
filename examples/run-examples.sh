#!/usr/bin/env bash
# run-examples.sh: reproduce every recipe of docs/EXAMPLES.md against a
# throwaway lab on this machine. Except the opt-in osint recipe, nothing
# leaves loopback: the targets are the simulators under simulators/, the
# captures are inline hex, and HOME points at a temporary directory, so
# your real ~/.elsereno is never read or written.
#
# Usage:
#   examples/run-examples.sh            # every recipe
#   examples/run-examples.sh scan       # only recipes whose id starts with "scan"
#   examples/run-examples.sh osint      # the one recipe that queries the internet
#                                       # (Shodan InternetDB); never run by default
#
# Needs: Go (to build the binary and the simulators), curl, python3.
set -euo pipefail
cd "$(CDPATH="" cd -- "$(dirname -- "$0")/.." && pwd)"
only="${1:-}"

lab="$(mktemp -d)"
pids=()
cleanup() {
	for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	rm -rf "$lab"
}
trap cleanup EXIT

echo ":: lab in $lab"
mkdir -p "$lab/bin" "$lab/home"
go build -o "$lab/bin/elsereno" ./cmd/elsereno
for s in modbus opcua slmp; do go build -o "$lab/bin/sim-$s" "./simulators/$s"; done
export HOME="$lab/home"
export PATH="$lab/bin:$PATH"
cp examples/targets.txt examples/scope.yaml examples/elsereno.yaml "$lab/"
cd "$lab"

# Simulators. Modbus listens on 1502: an unprivileged process cannot bind
# 127.0.0.1:502 on macOS or Linux.
sim-modbus --listen 127.0.0.1:1502 >/dev/null 2>&1 & pids+=("$!")
sim-opcua --addr 127.0.0.1:4840 >/dev/null 2>&1 & pids+=("$!")
sim-slmp --addr 127.0.0.1:5007 >/dev/null 2>&1 & pids+=("$!")
sleep 1

# The vault passphrase lives in a 0600 file, never in argv (PITF-032).
# A random value: this vault is thrown away with the lab.
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$lab/pp"

recipe() { # recipe <id> <title>
	# osint leaves loopback, so it runs only when asked for by name.
	if [ "$1" = osint ] && [ "$only" != osint ]; then return 1; fi
	case "$1" in "$only"*) ;; *) return 1 ;; esac
	printf '\n==== %s: %s\n' "$1" "$2"
}
run() { # run <command...>: print it, then run it; a failure is shown, not fatal
	printf '$ %s\n' "$*"
	"$@" 2>&1 || printf '[exit %s]\n' "$?"
}

if recipe info "Version, legal and preflight"; then
	run elsereno version
	run elsereno legal
	run elsereno doctor
fi

if recipe plugins "What this build can talk to"; then
	run elsereno plugins list
	printf '$ elsereno plugins ports | head -8\n'
	{ elsereno plugins ports || true; } | head -8
fi

if recipe config "Validate and format the configuration"; then
	run elsereno --config elsereno.yaml config lint
	run elsereno lint --config elsereno.yaml --scope scope.yaml
	printf '$ elsereno --config elsereno.yaml config show | head -12\n'
	{ elsereno --config elsereno.yaml config show 2>&1 || true; } | head -12
	run elsereno fmt elsereno.yaml
fi

if recipe vault "Vault and credentials"; then
	run elsereno vault init --vault-passphrase-file pp
	run elsereno vault status
	# creds reads two lines from stdin when there is no TTY: the vault
	# passphrase, then the value. Neither goes through argv.
	printf '$ { cat pp; echo lab-demo-value; } | elsereno creds store lab_demo\n'
	{ cat pp; echo lab-demo-value; } | elsereno creds store lab_demo 2>&1
	printf '$ elsereno creds list < pp\n'
	elsereno creds list < pp 2>&1
	printf '$ elsereno creds show lab_demo < pp\n'
	elsereno creds show lab_demo < pp 2>&1
fi

if recipe scan "Scan the lab"; then
	run elsereno scan --input list:targets.txt --scope scope.yaml --no-progress --output findings.ndjson
	printf '$ wc -l findings.ndjson\n'
	wc -l < findings.ndjson
	printf '$ head -1 findings.ndjson\n'
	head -1 findings.ndjson
	printf '$ one line per finding: port, protocol, severity, score\n'
	python3 -c 'import json,sys
for l in open("findings.ndjson"):
    f = json.loads(l); print(f["port"], f["protocol"], f["severity"], f["score"])'
	run elsereno scan --input list:targets.txt --scope scope.yaml --no-progress --plugin slmp --output-format csv
fi

if recipe triage "Triage, explain and why"; then
	run elsereno triage --from-file findings.ndjson
	printf '$ grep slmp findings.ndjson | elsereno explain\n'
	grep '"protocol":"slmp"' findings.ndjson | elsereno explain 2>&1 || true
	run elsereno why 127.0.0.1:5007
	run elsereno scoring show
	run elsereno scoring example
fi

if recipe standards "Standards mapping"; then
	run elsereno standards --protocol modbus
fi

if recipe discover "Discover open ICS ports"; then
	run elsereno discover --auto 127.0.0.1/32 --scope scope.yaml
fi

if recipe probe "Probe one service"; then
	run elsereno fingerprint probe --plugin modbus --target 127.0.0.1:1502
	run elsereno plaintext-check --target 127.0.0.1:1502
	run elsereno opcua probe-anon --target 127.0.0.1:4840
fi

if recipe offline "Offline decoders and monitors"; then
	# A captured Modbus exception reply (illegal data address).
	run elsereno fingerprint validate --plugin modbus --hex "0001 0000 0003 01 83 02"
	cat > modbus-frames.txt <<'FRAMES'
# read holding registers (benign)
0001 0000 0006 01 03 0000 000a
# write single register: a write on the wire
0002 0000 0006 01 06 0001 00ff
# diagnostics 0x08 sub-function 0x0001: restart communications
0003 0000 0006 01 08 0001 0000
FRAMES
	run elsereno modbus monitor --file modbus-frames.txt
	run elsereno goose decode --hex "010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860100 880101"
	run elsereno profinet encode-identify --xid 1
	run elsereno profinet decode --hex fefe0500cafebabe00010006ffff00020000 --strip-l2 0
fi

if recipe audit "Audit chain"; then
	run elsereno audit verify-file
fi

if recipe backup "Backup and restore"; then
	run elsereno backup create --out vault.bak --vault-passphrase-file pp
	run elsereno backup inspect --in vault.bak
	mkdir restored
	run elsereno backup restore --in vault.bak --to restored --vault-passphrase-file pp
	printf '$ ls restored\n'
	ls restored
fi

if recipe serve "Dashboard, API and schedules"; then
	elsereno serve --scan-store=memory --addr 127.0.0.1:18787 --vault-passphrase-file pp > serve.log 2>&1 &
	pids+=("$!")
	sleep 2
	printf '$ cat serve.log\n'
	cat serve.log
	u=http://127.0.0.1:18787
	printf '$ curl -s -o /dev/null -w "%%{http_code}\\n" %s/healthz\n' "$u"
	curl -s -o /dev/null -w "%{http_code}\n" "$u/healthz"
	printf '$ curl -s -X POST %s/api/v1/scans -H "X-Operator: alice" -d {...}\n' "$u"
	curl -s -X POST "$u/api/v1/scans" -H "X-Operator: alice" -H "Content-Type: application/json" \
		-d "{\"input\":\"list:$lab/targets.txt\",\"plugins\":[\"slmp\",\"opcua\"]}" \
		| python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["id"], d["state"])'
	sleep 3
	printf '$ curl -s %s/api/v1/scans -H "X-Operator: alice"\n' "$u"
	curl -s "$u/api/v1/scans" -H "X-Operator: alice" \
		| python3 -c 'import json,sys; [print(s["state"], s["stats"], s.get("findings_by_plugin")) for s in json.load(sys.stdin)["data"]]'
	printf '$ curl -s -X POST %s/api/v1/schedules -H "X-Operator: alice" -d {...}\n' "$u"
	curl -s -X POST "$u/api/v1/schedules" -H "X-Operator: alice" -H "Content-Type: application/json" \
		-d "{\"name\":\"lab-nightly\",\"template\":{\"input\":\"list:$lab/targets.txt\",\"plugins\":[\"slmp\"]},\"cron_expr\":\"0 2 * * *\",\"timezone\":\"Europe/Madrid\"}" \
		| python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["id"], d["name"], "next", d["next_fire_at"])'
	export ELSERENO_URL="$u"
	run elsereno schedule list
	id="$(elsereno schedule list --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')"
	run elsereno schedule disable "$id" --dry-run
	run elsereno schedule delete "$id"
	run elsereno schedule delete "$id" --dry-run
fi

if recipe api "API description"; then
	printf '$ elsereno api openapi | head -5\n'
	{ elsereno api openapi || true; } | head -5
fi

if recipe osint "Passive OSINT with Shodan InternetDB (queries the internet)"; then
	# 192.0.2.10 is a documentation address (RFC 5737): InternetDB has no
	# data for it. Put an address you are authorised to test in its place.
	printf '$ curl -s https://internetdb.shodan.io/192.0.2.10\n'
	curl -s https://internetdb.shodan.io/192.0.2.10
	echo
	run elsereno scan --input internetdb:192.0.2.10 --scope scope.yaml --no-progress
	run elsereno scan --input internetdb:192.0.2.0/24 --no-progress
fi

echo
echo ":: done"
