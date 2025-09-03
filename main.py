import subprocess
import os
def main():
    packages=subprocess.run(['pacman','-Q'], capture_output=True, text=True)
    cves= subprocess.run(['curl',
                          'https://security.archlinux.org'], capture_output=True, text=True)
    vulnerable_packages=[];
    fixes_available=[];
    cve_entries = deserialize(cves.stdout)
    for entry in cve_entries:
            if entry.name_version in packages.stdout.splitlines():
                vulnerable_packages.append(entry.name)
                if entry.fixed!=None:
                    fixes_available.append(entry.name)
                print(f"CVE: {entry.name}, Severity: {entry.severity}, Status: {entry.status} Fixed: {entry.fixed}")
    if len(fixes_available)>0:
        print(f"{len(fixes_available)} are vulnerable with fix available. Install?")
        fix_vulnerable = input().strip().lower()
        if fix_vulnerable == "" or fix_vulnerable in ["y", "yes"]:
            os.system(f"sudo pacman -S <affected_packages")
    else: 
        print(f"{len(vulnerable_packages)} affected packages without fix available. List[L/n]?")
        list_vulnerable=input().strip().lower()
        if list_vulnerable=="" or list_vulnerable=="l":
            for e in vulnerable_packages:
                print(f"{e} affected")


          
def deserialize(content):
    import logging
    import re
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger(__name__)
    entries = []
    try:
        if not content or not content.strip():
            logger.warning("Empty content provided to deserialize function")
            return entries
        tr_pattern = r'<tr>\s*<td><a href="/AVG-\d+">(AVG-\d+)</a></td>\s*<td>(.*?)</td>\s*<td class="wrap">\s*<span class="no-wrap"><a href="/package/([^"]+)">([^<]+)</a></span>\s*</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td><span class="[^"]*">([^<]*)</span></td>\s*<td><span class="[^"]*">([^<]*)</span></td>'
        matches = re.findall(tr_pattern, content, re.DOTALL)
        if not matches:
            logger.warning("No table rows matching expected pattern found in HTML content")
            return entries
        for match in matches:
            try:
                if len(match) != 8:
                    logger.warning(f"Unexpected match format: expected 8 fields, got {len(match)}")
                    continue
                avg_id, cves_html, package_name, package_display, version, fixed_version, severity, status = match
                if not package_display or not package_display.strip():
                    logger.warning(f"Empty package name found in row with AVG ID: {avg_id}")
                    continue
                package_display = package_display.strip()
                version = version.strip()
                fixed_version = fixed_version.strip()
                severity = severity.strip() if severity.strip() else "Unknown"
                status = status.strip() if status.strip() else "Unknown"
                cve_pattern = r'CVE-\d{4}-\d+'
                cves = re.findall(cve_pattern, cves_html)
                package_with_version = f"{package_display} {version}" if version else package_display
                entry_obj = entry(
                    name=package_display,
                    name_version=package_with_version,
                    severity=severity,
                    status=status,
                    fixed=fixed_version if fixed_version else None
                )
                entries.append(entry_obj)
            except Exception as e:
                logger.warning(f"Error parsing table row match: {e}")
                continue
    except Exception as e:
        logger.error(f"Critical error in deserialize function: {e}")
        return entries
    if not entries:
        logger.warning("No valid entries extracted from content")
    else:
        logger.info(f"Successfully parsed {len(entries)} security entries")
    return entries


class entry:
    def __init__(self, name, name_version, severity, status=None, fixed=None ):
        self.name=name
        self.name_version=name_version
        self.severity=severity
        self.status=status
        self.fixed=fixed







if __name__ == "__main__":
    main()