from django.conf import settings
import json
import requests


DOMAIN_ENDPOINT = "https://www.virustotal.com/api/v3/domains/{domain}"
IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def call_api(endpoint):
    headers = {"x-apikey": settings.VIRUS_TOTAL_API_KEY}
    response = requests.get(endpoint, headers=headers)
    return json.loads(response.text)


def virus_total_report(value_type, data):
    result = {}
    if value_type == "ip":
        result = call_api(IP_ENDPOINT.format(ip=data))
    elif value_type == "domain":
        result = call_api(DOMAIN_ENDPOINT.format(domain=data))

    return result
