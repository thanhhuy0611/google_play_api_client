API Client for Google Play
==============================
- Download report csv file
- Generate access_token to access Google Play Developer API

Getting Started
------------

Setup:
- `pip install --upgrade google-cloud-storage`
- Download private key json file of service account then add it as `service_account.json` to root project

Usage:
------------

Download report csv file:
- `python3 download_report.py`
- Check file ./report.csv

Generate access_token to access Google Play Developer API:
- `python3 generate_access_token.py`
- Check file ./access_token.text

