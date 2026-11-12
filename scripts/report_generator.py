from datetime import datetime


def generate_report(results):

    with open("investigation_report.txt", "w") as report:

        report.write("================================================================================\n")
        report.write("        THREAT HUNTER TOOLKIT — INVESTIGATION REPORT\n")
        report.write("================================================================================\n")
        report.write(f"Generated: {datetime.now()}\n\n")

        # ===================== EXECUTIVE SUMMARY =====================
        report.write("EXECUTIVE SUMMARY\n")
        report.write("------------------------------------------------------------\n")

        auth = results.get("auth_detection", {})
        ps = results.get("powershell_detection", [])
        ioc = results.get("ioc_detection", [])

        total_auth = len(auth.get("suspicious_ips", {}))
        total_ps = len(ps)
        total_ioc = len(ioc)

        report.write(f"Brute-force IPs detected: {total_auth}\n")
        report.write(f"Suspicious PowerShell commands: {total_ps}\n")
        report.write(f"IOC matches: {total_ioc}\n\n")

        report.write("Key Findings:\n")

        for ip, data in auth.get("suspicious_ips", {}).items():
            report.write(f"[!] Brute-force activity from {ip} ({data['count']} attempts)\n")

        for item in ps[:3]:
            report.write(f"[!] Suspicious PowerShell on line {item['line']}\n")

        if total_ioc > 0:
            report.write("[!] Known malicious indicators detected in logs\n")

        report.write("\n")

        # ===================== AUTH SECTION =====================
        report.write("AUTHENTICATION ANALYSIS\n")
        report.write("------------------------------------------------------------\n")

        if auth.get("suspicious_ips"):
            for ip, data in auth["suspicious_ips"].items():
                report.write(
                    f"{ip} | Attempts: {data['count']} | Severity: {data['severity']} | Targets: {', '.join(data['targets'])}\n"
                )
        else:
            report.write("No brute-force behaviour detected\n")

        report.write("\n")

        # ===================== POWERSHELL =====================
        report.write("POWERSHELL ANALYSIS\n")
        report.write("------------------------------------------------------------\n")

        if ps:
            for item in ps[:10]:
                report.write(
                    f"Line {item['line']} | Patterns: {', '.join(item['patterns'])} | Severity: {item['severity']}\n"
                )

                if item.get("decoded"):
                    report.write(f"Decoded: {item['decoded']}\n")
        else:
            report.write("No suspicious PowerShell activity detected\n")

        report.write("\n")

        # ===================== IOC =====================
        report.write("IOC MATCHES\n")
        report.write("------------------------------------------------------------\n")

        if ioc:
            for match in ioc[:10]:
                report.write(
                    f"{match['ioc']} found in {match['file']} (Line {match['line']})\n"
                )
        else:
            report.write("No IOC matches detected\n")

        report.write("\n")

        # ===================== ACCESS =====================
        report.write("ACCESS LOG ANALYSIS\n")
        report.write("------------------------------------------------------------\n")

        access = results.get("access_detection", {})
        suspicious_access = access.get("suspicious_ips", {})

        if suspicious_access:
            for ip, count in suspicious_access.items():
                report.write(f"{ip} — {count} requests\n")
        else:
            report.write("No abnormal web traffic detected\n")

        report.write("\n================================================================================\n")
        report.write("END OF REPORT\n")

    print("Investigation report generated.")
