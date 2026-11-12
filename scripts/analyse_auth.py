import re


def get_severity(count):
    """
    Assign severity level based on number of failed attempts.
    """
    if count >= 25:
        return "CRITICAL"
    elif count >= 11:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def analyse_auth_log(filepath, threshold=5):
    """
    Analyse authentication logs to detect brute-force login attempts.

    Parameters:
        filepath (str): Path to auth.log file
        threshold (int): Minimum failed attempts to flag an IP

    Returns:
        dict: Summary of findings including counts, suspicious IPs, and sample lines
    """

    failed_counts = {}
    user_targets = {}
    flagged_lines = []

    try:
        with open(filepath, "r") as file:

            for line in file:
                line_lower = line.lower()

               
                if "failed password" in line_lower or "authentication failure" in line_lower:

                   
                    ip_match = re.search(r'\b\d+\.\d+\.\d+\.\d+\b', line)
                    if not ip_match:
                        continue

                    ip = ip_match.group()

                   
                    failed_counts[ip] = failed_counts.get(ip, 0) + 1

                   
                    user_match = re.search(r'Failed password for (\w+)', line)
                    if user_match:
                        user = user_match.group(1)

                        if ip not in user_targets:
                            user_targets[ip] = set()

                        user_targets[ip].add(user)

                
                    flagged_lines.append(line.strip())

       
        suspicious_ips = {}

        for ip, count in failed_counts.items():
            if count >= threshold:
                suspicious_ips[ip] = {
                    "count": count,
                    "severity": get_severity(count),
                    "targets": list(user_targets.get(ip, []))
                }

        return {
            "total_failed_attempts": sum(failed_counts.values()),
            "ip_counts": failed_counts,
            "suspicious_ips": suspicious_ips,
            "sample_lines": flagged_lines[:5]
        }

    except FileNotFoundError:
        return {"error": f"File not found: {filepath}", "findings": []}

    except PermissionError:
        return {"error": f"Permission denied: {filepath}", "findings": []}

    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "findings": []}



if __name__ == "__main__":
    result = analyse_auth_log("logs/auth.log")
    print(result)
