#!/bin/bash

echo "=============================================="
echo " AI CLOUD CYBERSECURITY - AUTOMATED TESTS"
echo "=============================================="
echo

echo "[1/2] Running security regression tests..."
pytest -v

TEST_RESULT=$?

echo
echo "=============================================="

if [ $TEST_RESULT -eq 0 ]; then
    echo " SECURITY TEST STATUS: PASSED"
    echo " All automated security tests passed."
else
    echo " SECURITY TEST STATUS: FAILED"
    echo " One or more security tests failed."
fi

echo "=============================================="

exit $TEST_RESULT
