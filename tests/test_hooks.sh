#!/usr/bin/env bash
# Hook self-tests: pipe fixture JSON into each guard and assert the exit code.
# 2 = blocked (expected for dangerous inputs), 0 = allowed.
set -u
H=".claude/hooks"
fail=0
run() { # $1 script  $2 fixture  $3 expected_code  $4 label
  cat "tests/fixtures/$2" | bash "$H/$1" >/dev/null 2>&1
  got=$?
  if [ "$got" = "$3" ]; then
    echo "  PASS  $4  (exit $got)"
  else
    echo "  FAIL  $4  (expected $3, got $got)"; fail=1
  fi
}

echo "zt-guard.sh (Bash):"
run zt-guard.sh        bash_rm_rf.json        2 "block rm -rf /"
run zt-guard.sh        bash_pipe_shell.json   2 "block curl | bash"
run zt-guard.sh        bash_force_push.json   2 "block git force-push"
run zt-guard.sh        bash_read_env.json     2 "block cat .env"
run zt-guard.sh        bash_tamper_policy.json 2 "block policy tamper"
run zt-guard.sh        bash_safe.json         0 "allow npm test"

echo "zt-file-guard.sh (Read/Edit/Write):"
run zt-file-guard.sh   read_env.json          2 "block read .env"
run zt-file-guard.sh   edit_policy.json       2 "block edit policy"
run zt-file-guard.sh   read_src.json          0 "allow read source"

echo "zt-secret-scan.sh (Write/Edit):"
run zt-secret-scan.sh  write_secret.json      2 "block write with AWS key"
run zt-secret-scan.sh  write_clean.json       0 "allow clean write"

echo
[ "$fail" = 0 ] && echo "ALL HOOK TESTS PASSED" || echo "SOME HOOK TESTS FAILED"
exit $fail
