#!/bin/bash
# Live interop scenarios against the PBX over loopback UDP.
# Usage: ./interop/run.sh [--slow]
#   default: S1,S3,S4+S5,S6,S7 (~15s). --slow adds S8 (Timer-B 408, ~40s).
# Exits non-zero on any scenario failure.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INT="$ROOT/interop"
LOGS="$INT/logs"
PBX_HOST=127.0.0.1
PBX_PORT=5060
UAS_PORT=5070
UAC_PORT=5061
SLOW=0
if [ "${1:-}" = "--slow" ]; then
    SLOW=1
fi

PASS=0
FAIL=0

cd "$ROOT"
mkdir -p "$LOGS"
rm -f "$LOGS"/*

echo "== build =="
zig build || exit 1

echo "== start pbx =="
./zig-out/bin/micro_pbx >"$LOGS/pbx.log" 2>&1 &
PBX_PID=$!

trap 'kill $PBX_PID 2>/dev/null; wait 2>/dev/null' EXIT
sleep 2

# run_uac <name> <xml> [port] (default caller port)
run_uac() {
    local port="${3:-$UAC_PORT}"
    echo "== $1 =="
    if sipp $PBX_HOST:$PBX_PORT -i $PBX_HOST -p "$port" -sf "$INT/$2" -m 1 \
        -timeout 30s -timeout_error \
        -trace_msg -message_file "$LOGS/$1-uac-msg.log" \
        -trace_err -error_file "$LOGS/$1-uac-err.log" \
        -log_file "$LOGS/$1-uac.log" >"$LOGS/$1-out.txt" 2>&1; then
        echo "PASS $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL $1 (see $LOGS/$1-*)"
        FAIL=$((FAIL + 1))
    fi
    sleep 1
}

# run_uas_bg <name> <xml> <port>  -> sets RUN_UAS_PID (no command
# substitution: $! must be captured in this shell to remain wait()able).
run_uas_bg() {
    sipp $PBX_HOST:$PBX_PORT -i $PBX_HOST -p "$3" -sf "$INT/$2" -m 1 \
        -timeout 60s -timeout_error \
        -trace_msg -message_file "$LOGS/$1-uas-msg.log" \
        -trace_err -error_file "$LOGS/$1-uas-err.log" \
        -log_file "$LOGS/$1-uas.log" >"$LOGS/$1-uas-out.txt" 2>&1 &
    RUN_UAS_PID=$!
}

# S1: baseline REGISTER.
run_uac "s1-register" "uac-register-alice.xml"

# S3: unknown user, 404 once; the duplicate INVITE's replay is asserted
# via the PBX log (sipp discards it: its own INVITE transaction already
# completed on the first 404).
REPLAY_BEFORE=$(grep -c "retransmission detected" "$LOGS/pbx.log" || true)
run_uac "s3-unknown" "uac-unknown.xml"

REPLAY_AFTER=$(grep -c "retransmission detected" "$LOGS/pbx.log" || true)
if [ "$REPLAY_AFTER" -gt "$REPLAY_BEFORE" ]; then
    echo "PASS s3-replay (pbx replayed cached 404)"
    PASS=$((PASS + 1))
else
    echo "FAIL s3-replay (no retransmission replay in pbx log)"
    FAIL=$((FAIL + 1))
fi

# S7: exhausted Max-Forwards -> 483, no dialog.
run_uac "s7-max-forwards" "uac-mf0.xml"

# S4+S5: full call; the caller sends a duplicate INVITE mid-dialog that
# the PBX must absorb (second 100, no re-forward).
# Bob registers first (foreground, deterministic order), then the dialog
# UAS listens on the same port.
run_uac "s4-reg-bob" "uas-reg.xml" $UAS_PORT
sleep 1
echo "== s4-call/s5-absorb: start uas =="
run_uas_bg "s4-call" "uas-answer.xml" $UAS_PORT
UAS_PID=$RUN_UAS_PID

sleep 1
run_uac "s4-call" "uac-alice-call.xml"
wait "$UAS_PID"
UAS_RC=$?
if [ $UAS_RC -eq 0 ]; then
    echo "PASS s4-call-uas"
    PASS=$((PASS + 1))
else
    echo "FAIL s4-call-uas (see $LOGS/s4-call-uas-*)"
    FAIL=$((FAIL + 1))
fi

INVITES=$(grep -c "^INVITE sip:" "$LOGS/s4-call-uas-msg.log" || true)
# Distinct PBX Via branches on INVITE blocks only (ACK/BYE mint fresh PBX
# branches by design; Timer-A retransmits share one). sipp folds multi-Via
# lines with commas, hence cut. Any second branch here would prove a caller
# retransmit was re-forwarded. Raw count is timing-sensitive, so only the
# branch cardinality gates.
BRANCHES=$(grep -A8 "^INVITE sip:" "$LOGS/s4-call-uas-msg.log" | grep "^Via: SIP/2.0/UDP 127.0.0.1:$PBX_PORT;branch=" | tr -d '\r' | cut -d, -f1 | sort -u | wc -l)
echo "info s5-absorb (uas saw $INVITES INVITEs / $BRANCHES PBX branches)"
if [ "$BRANCHES" -eq 1 ]; then
    echo "PASS s5-absorb (single PBX branch: no re-forward)"
    PASS=$((PASS + 1))
else
    echo "FAIL s5-absorb (want 1 PBX branch)"
    FAIL=$((FAIL + 1))
fi
sleep 1

# S6: CANCEL race (bob re-registers first; same port as the dialog UAS).
run_uac "s6-reg-bob" "uas-reg.xml" $UAS_PORT
sleep 1
echo "== s6-cancel: start uas =="
run_uas_bg "s6-cancel" "uas-cancel.xml" $UAS_PORT
UAS_PID=$RUN_UAS_PID

sleep 1
run_uac "s6-cancel" "uac-alice-cancel.xml"
wait "$UAS_PID"
UAS_RC=$?
if [ $UAS_RC -eq 0 ]; then
    echo "PASS s6-cancel-uas"
    PASS=$((PASS + 1))
else
    echo "FAIL s6-cancel-uas (see $LOGS/s6-cancel-uas-*)"
    FAIL=$((FAIL + 1))
fi
sleep 1

# S8 (slow only): silent contact -> Timer B 408.
if [ $SLOW -eq 1 ]; then
    run_uac "s8-reg-silent" "uac-reg-silent.xml"
    run_uac "s8-invite-silent" "uac-invite-silent.xml"
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ $FAIL -eq 0 ]
