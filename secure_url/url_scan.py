from django.conf import settings
import json
import requests


URL_SCAN_ENDPOINT = "https://urlscan.io/api/v1/search/?q={type}:{value}"


def call_api(endpoint):
    # headers = {"API-Key": settings.VIRUS_TOTAL_API_KEY, 'Content-Type':'application/json'}
    # data = {"url": url, "visibility": "public"}
    # response = requests.get(endpoint, headers=headers)
    response = requests.get(endpoint)
    return json.loads(response.text)


def url_scan_report(value_type, data):
    result = {}
    if value_type == "ip":
        result = call_api(URL_SCAN_ENDPOINT.format(type="ip", value=data))
    elif value_type == "domain":
        result = call_api(URL_SCAN_ENDPOINT.format(type="domain", value=data))

    return result
