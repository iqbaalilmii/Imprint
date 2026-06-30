import os
import sys
import asyncio
import requests
import logging
import ipaddress

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("virustotal_checker")

def is_valid_public_ip(ip: str) -> bool:
    """
    Check if the given IP address is valid and is a public IPv4/IPv6 address.
    Excluded: private ranges, loopback, link-local, multicast, etc.
    """
    if not ip:
        return False
    ip = ip.strip()
    # Strip any port formatting or enclosing brackets just in case
    if ip.startswith('[') and ']' in ip:
        ip = ip.split(']')[0].replace('[', '')
    if ip in ["0.0.0.0", "127.0.0.1", "::1", "::", "*", "-", "N/A"]:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified)
    except ValueError:
        return False

async def check_ips_with_virustotal(unique_ips: list[str], api_key: str) -> dict:
    """
    Check unique IPs with VirusTotal API v3.
    """
    if not api_key:
        logger.warning("VirusTotal API key is empty/not configured. Skipping VirusTotal check.")
        return {}

    # Filter out invalid and private IPs
    public_ips = []
    for ip in unique_ips:
        cleaned_ip = ip.strip()
        if is_valid_public_ip(cleaned_ip):
            public_ips.append(cleaned_ip)

    # ponytail: limit checks to the first 10 public IPs to respect rate limits (max 4 req/min)
    # and prevent analysis from hanging too long.
    ips_to_check = public_ips[:10]
    if len(public_ips) > 10:
        logger.info(f"More than 10 unique IPs detected ({len(public_ips)} total). Restricting checks to the first 10.")

    results = {}
    for idx, ip in enumerate(ips_to_check):
        if idx > 0:
            logger.info("Waiting 15 seconds to respect VirusTotal rate limit...")
            await asyncio.sleep(15)
            
        logger.info(f"Querying VirusTotal for IP: {ip} ({idx + 1}/{len(ips_to_check)})...")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        
        try:
            # Execute requests.get in thread pool to prevent blocking the event loop
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: requests.get(url, headers=headers, timeout=10)
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                results[ip] = {
                    'malicious_count': malicious_count,
                    'total_engines': total_engines
                }
                logger.info(f"IP {ip} scan completed: {malicious_count}/{total_engines} malicious engines")
            elif response.status_code == 404:
                logger.info(f"IP {ip} not found in VirusTotal database (404). Returning zero hits.")
                results[ip] = {
                    'malicious_count': 0,
                    'total_engines': 0
                }
            else:
                logger.warning(f"VirusTotal API warning for IP {ip}: status code {response.status_code}")
        except Exception as e:
            logger.warning(f"VirusTotal request error/timeout for IP {ip}: {e}")
            
    return results

def build_virustotal_lookup(netscan_output: list, vt_results: dict) -> dict:
    """
    Build VirusTotal lookup mapping for PIDs using the scan results.
    """
    lookup = {}
    for conn in (netscan_output or []):
        pid = conn.get("PID") or conn.get("pid")
        if pid is None:
            continue
            
        try:
            pid_val = int(pid)
        except ValueError:
            continue
            
        foreign_addr = conn.get("ForeignAddr") or conn.get("foreign_addr") or conn.get("foreign") or conn.get("ForeignAddress")
        if not foreign_addr:
            continue
            
        ip_candidate = str(foreign_addr).strip()
        # Parse IP from IP:Port or [IP]:Port formatting
        if ':' in ip_candidate:
            if ip_candidate.startswith('[') and ']' in ip_candidate:
                ip_candidate = ip_candidate.split(']')[0].replace('[', '')
            elif ip_candidate.count(':') == 1:
                ip_candidate = ip_candidate.split(':')[0]
                
        ip_candidate = ip_candidate.strip()
        
        if ip_candidate in vt_results:
            stats = vt_results[ip_candidate]
            ioc_dict = {
                'ioc_type': 'ip',
                'value': ip_candidate,
                'malicious_count': stats.get('malicious_count', 0),
                'total_engines': stats.get('total_engines', 0)
            }
            if pid_val not in lookup:
                lookup[pid_val] = []
            
            # Avoid duplicate connections under the same PID
            if not any(item['value'] == ip_candidate for item in lookup[pid_val]):
                lookup[pid_val].append(ioc_dict)
                
    return lookup
