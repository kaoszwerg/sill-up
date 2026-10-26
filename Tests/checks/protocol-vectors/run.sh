#!/bin/bash
# The test vectors of docs/protocol/vectors.json, computed again from Sources/StreamProtocol: the file
# must be byte for byte what the code gives (its certificate and kind 18 signature, the two random
# values, kept once they verify again). A change to the wire, the pairing or a rule it covers fails
# here until the file is regenerated and docs/protocol/SPEC.md says what changed.
#   Tests/checks/protocol-vectors/run.sh            check docs/protocol/vectors.json
#   Tests/checks/protocol-vectors/run.sh --write    regenerate it (keeping the certificate and signature)
#   Tests/checks/protocol-vectors/run.sh --fresh    regenerate it with a new certificate and signature
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../common.sh"
committed="$root/docs/protocol/vectors.json"
swiftc -O Sources/StreamProtocol/*.swift "$here/main.swift" -o "$out/vectors"
case "${1:-}" in
    --write) "$out/vectors" "$out/vectors.json" --reuse "$committed" && cp "$out/vectors.json" "$committed" ;;
    --fresh) "$out/vectors" "$committed" ;;
    "")
        [ -f "$committed" ] || { echo "protocol-vectors: $committed is missing" >&2; exit 1; }
        "$out/vectors" "$out/vectors.json" --reuse "$committed"
        if ! diff -u "$committed" "$out/vectors.json" > "$out/diff.txt"; then
            echo "protocol-vectors: docs/protocol/vectors.json differs from what the code gives ($out/diff.txt):" >&2
            head -n 40 "$out/diff.txt" >&2
            exit 1
        fi
        echo "protocol-vectors: docs/protocol/vectors.json matches the code"
        python3 -I "$here/crosscheck.py" "$committed" ;;
    *) echo "usage: $0 [--write|--fresh]" >&2; exit 2 ;;
esac
