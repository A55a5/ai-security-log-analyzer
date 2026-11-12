import re
import base64


def get_severity(patterns_found):
    """
    Assign severity based on detected patterns.
    """
    if "-EncodedCommand" in patterns_found and "DownloadString" in patterns_found:
        return "CRITICAL"
    elif "-EncodedCommand" in patterns_found:
        return "HIGH"
    elif "DownloadString" in patterns_found:
        return "HIGH"
    elif "-ExecutionPolicy Bypass" in patterns_found:
        return "HIGH"
    elif "Invoke-WebRequest" in patterns_found:
        return "MEDIUM"
    else:
        return "LOW"


def decode_base64_command(command):
    """
    Attempt to extract and decode Base64 encoded PowerShell commands.
    """
    match = re.search(r'-EncodedCommand\s+([A-Za-z0-9+/=]+)', command, re.IGNORECASE)
    if match:
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            return decoded
        except Exception:
            return None
    return None


def analyse_powershell_log(filepath):
    """
    Analyse PowerShell logs for suspicious commands.
    """

    suspicious_patterns = [
        "-EncodedCommand",
        "-ExecutionPolicy Bypass",
        "Invoke-WebRequest",
        "DownloadString"
    ]

    findings = []

    try:
        with open(filepath, "r") as file:

            for line_number, line in enumerate(file, start=1):
                line_lower = line.lower()

                matched_patterns = []

                for pattern in suspicious_patterns:
                    if pattern.lower() in line_lower:
                        matched_patterns.append(pattern)

                if matched_patterns:
                    decoded_command = None

                    if "-EncodedCommand" in matched_patterns:
                        decoded_command = decode_base64_command(line)

                    findings.append({
                        "line": line_number,
                        "patterns": matched_patterns,
                        "severity": get_severity(matched_patterns),
                        "command": line.strip(),
                        "decoded": decoded_command
                    })

        return findings

    except FileNotFoundError:
        return {"error": f"File not found: {filepath}", "findings": []}

    except PermissionError:
        return {"error": f"Permission denied: {filepath}", "findings": []}

    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "findings": []}


if __name__ == "__main__":
    results = analyse_powershell_log("logs/powershell_log.txt")
    print(results)
