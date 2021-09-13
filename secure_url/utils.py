import re


def set_malicious_flag(virus_total_values, url_scan_values):
    virus_total_ip_is_malicious = False
    virus_total_url_is_malicious = False
    if "ip" in virus_total_values:
        last_analysis_values = virus_total_values["ip"]["data"]["attributes"]["last_analysis_stats"]
        virus_total_ip_is_malicious = (last_analysis_values["malicious"] > 5/100*(sum(last_analysis_values.values())))
    if "url" in virus_total_values:
        last_analysis_values = virus_total_values["url"]["data"]["attributes"]["last_analysis_stats"]
        virus_total_url_is_malicious = (last_analysis_values["malicious"] > 5/100*(sum(last_analysis_values.values())))
    
    return virus_total_ip_is_malicious or virus_total_url_is_malicious


def validate_by_type(value_type, data):
    if value_type == "domain":
        return validate_url(data)
    elif value_type == "ip":
        return validate_ip(data)
    else:
        return False


def validate_url(url):
    regex = re.compile(
        r'[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z]+',
        re.IGNORECASE
    )
    return url is not None and regex.search(url)


def validate_ip(ip):
    regex = re.compile(
        r'[0-9]+\.[0-9]+.[0-9]+\.[0-9]'
    )
    return ip is not None and regex.search(ip)
