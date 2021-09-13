import json
from rest_framework.response import Response
from rest_framework.views import APIView
from secure_url.url_scan import url_scan_report
from secure_url.utils import set_malicious_flag, validate_by_type
from secure_url.virus_total import virus_total_report


def get_response(value_type, data):
    url_scan_response = url_scan_report(value_type, data)
    virus_total_response = virus_total_report(value_type, data)
    malicious_flag = set_malicious_flag(virus_total_response, url_scan_response)
    return {
        "virustotal": virus_total_response,
        "urlscan": url_scan_response,
        "malicious": malicious_flag
    }


class Service(APIView):
    
    def get(self, request):
        value_type = request.query_params.get("type")
        data = request.query_params.get("data", None)
        if validate_by_type(value_type, data):
            return Response(get_response(value_type, data))
        else:
            return Response({"Error": "Invalid format"})

    def post(self, request):
        json_body = json.loads(request.body.decode("utf-8"))
        value_type = json_body.get("type")
        data = json_body.get("data", None)
        if validate_by_type(value_type, data):
            return Response(get_response(value_type, data))
        else:
            return Response({"Error": "Invalid format"})


class ServiceIP(APIView):
    
    def get(self, request, ip):
        value_type = "ip"
        if validate_by_type(value_type, ip):
            return Response(get_response(value_type, ip))
        else:
            return Response({"Error": "Invalid format"})


class ServiceDomain(APIView):
    
    def get(self, request, domain):
        value_type = "domain"
        if validate_by_type(value_type, domain):
            return Response(get_response(value_type, domain))
        else:
            return Response({"Error": "Invalid format"})
