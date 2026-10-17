#!/bin/sh
set -e

# Loop through all test files and execute them with the fh binary
for a in tests/test_*.fh; do
  echo "Running $a..."
  ./fh "$a"
done

echo "All tests passed!"
