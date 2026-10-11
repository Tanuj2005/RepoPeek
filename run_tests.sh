```bash
#!/usr/bin/env bash

# Usage:
# ./run_tests.sh          -> Run all tests
# ./run_tests.sh unit     -> Run unit tests
# ./run_tests.sh integration
# ./run_tests.sh security
# ./run_tests.sh perf

set -u
cd "$(dirname "$0")"
mkdir -p reports

case "${1:-all}" in
    unit)
        T="tests/test_1_unit.py"
        ;;
    integration)
        T="tests/test_2_integration_api.py"
        ;;
    security)
        T="tests/test_3_security.py"
        ;;
    perf)
        T="tests/test_4_performance_load.py"
        ;;
    *)
        T="tests"
        ;;
esac

python -m pytest "$T" -v \
    --cov=src \
    --cov-branch \
    --cov-report=term-missing \
    --cov-report=html:reports/coverage \
    --html=reports/test_report.html \
    --self-contained-html \
    --junitxml=reports/junit.xml

echo
echo "Open reports/test_report.html (results)"
echo "Open reports/coverage/index.html (coverage)"
```