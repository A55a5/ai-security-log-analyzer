from analyse_auth import analyse_auth_log
from analyse_powershell import analyse_powershell_log
from analyse_ioc import analyse_all_logs_for_iocs
from analyse_access import analyse_access_log
from report_generator import generate_report


def run_investigation():

    print("=== Threat Hunter Toolkit ===")
    print("Starting investigation...\n")

    auth_results = analyse_auth_log("logs/auth.log")
    print("✓ Auth analysis complete")

    powershell_results = analyse_powershell_log("logs/powershell_log.txt")
    print("✓ PowerShell analysis complete")

    ioc_results = analyse_all_logs_for_iocs(
        ["logs/access.log", "logs/auth.log", "logs/powershell_log.txt"],
        "logs/ioc.txt"
    )
    print("✓ IOC analysis complete")

    access_results = analyse_access_log("logs/access.log")
    print("✓ Access log analysis complete")

    results = {
        "auth_detection": auth_results,
        "powershell_detection": powershell_results,
        "ioc_detection": ioc_results,
        "access_detection": access_results
    }

    return results


if __name__ == "__main__":

    investigation_results = run_investigation()

    generate_report(investigation_results)

    print("\nInvestigation complete. Report generated.\n")
