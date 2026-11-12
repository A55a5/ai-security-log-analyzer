"""
analyse_access.py
Detect suspicious activity in web access logs
"""

from collections import defaultdict


def analyse_access_log(filepath, threshold=20):

    ip_requests = defaultdict(int)
    suspicious_ips = {}

    try:

        with open(filepath, "r") as file:

            for line in file:

                ip = line.split()[0]
                ip_requests[ip] += 1

        for ip, count in ip_requests.items():

            if count >= threshold:
                suspicious_ips[ip] = count

        return {
            "total_ips": len(ip_requests),
            "suspicious_ips": suspicious_ips
        }

    except FileNotFoundError:
        print(f"Error: File not found -> {filepath}")
        return None


if __name__ == "__main__":

    results = analyse_access_log("logs/access.log")

    print(results)
