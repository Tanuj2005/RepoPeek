@echo off
REM Windows: run_tests.bat
if not exist reports mkdir reports
python -m pytest tests -v --cov=src --cov-branch --cov-report=term-missing --cov-report=html:reports/coverage --html=reports/test_report.html --self-contained-html --junitxml=reports/junit.xml
echo.
echo Open reports\test_report.html and reports\coverage\index.html
