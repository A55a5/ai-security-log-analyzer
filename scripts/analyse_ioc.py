import re


def load_iocs(filepath):
    ips = set()
    urls = set()

    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    ips.add(line)
                else:
                    urls.add(line)

        return ips, urls

    except Exception:
        return set(), set()


def scan_file_for_iocs(filepath, ips, urls):
    findings = []

    try:
        with open(filepath, "r") as file:
            for line_number, line in enumerate(file, start=1):

                found_ips = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', line)

                for ip in found_ips:
                    if ip in ips:
                        findings.append({
                            "ioc": ip,
                            "file": filepath,
                            "line": line_number,
                            "context": line.strip()
                        })

                for url in urls:
                    if url in line:
                        findings.append({
                            "ioc": url,
                            "file": filepath,
                            "line": line_number,
                            "context": line.strip()
                        })

    except Exception:
        pass

    return findings


def analyse_all_logs_for_iocs(log_files, ioc_file):

    ips, urls = load_iocs(ioc_file)
    all_findings = []

    for log in log_files:
        all_findings.extend(scan_file_for_iocs(log, ips, urls))

    return all_findings
