import xml.etree.ElementTree as ET

def parse_nmap_vulns(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    print(f"--- 🛡️ VULNERABILITY ASSESSMENT REPORT ---")
    
    for host in root.findall('host'):
        ip = host.find('address').attrib['addr']
        print(f"\n[+] Target IP: {ip}")
        
        for port in host.findall('.//port'):
            port_id = port.attrib['portid']
            service = port.find('service').attrib.get('name', 'unknown')
            
            for script in port.findall('script'):
                if script.attrib['id'] == 'vulners':
                    print(f"    - Port {port_id} ({service}) is VULNERABLE:")
                    # This cleans up the messy Nmap output
                    print(script.attrib['output'].strip())

if __name__ == "__main__":
    parse_nmap_vulns('vuln_scan_results.xml')
