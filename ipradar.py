"""
IPradar: Lightweight IP reconnaissance script
-------------------------------------------

This script provides a simple command‑line tool for performing basic
reconnaissance on IP addresses.  It supports several optional
capabilities:

1. **IP location lookup** via the `ipwhois` Python package.  The
   library’s RDAP functionality is used because RDAP provides a
   structured JSON representation of the whois information, including
   network details and country codes【319599820089173†L3-L7】.  To use
   this feature you must install the `ipwhois` package (`pip install
   ipwhois`).

2. **Shodan search** via the official Python library.  The Shodan API
   lets you search for hosts that match certain criteria and retrieve
   detailed information about a specific IP.  Before using this
   feature you need to obtain an API key from Shodan and install the
   `shodan` package.  The basic usage pattern is to initialize an
   API client with your key (`api = shodan.Shodan(YOUR_KEY)`) and
   then call `api.search()` or `api.host()`【473135104521006†L45-L67】.  The
   script wraps these calls and prints summary information.

3. **Censys search** using the `censys` Python module.  Censys
   provides a modern API for searching hosts across the Internet and
   retrieving structured host data.  The v2 API exposes a `CensysHosts`
   class for querying the hosts index and the `view` method to
   retrieve details for a specific IP【468786160087640†L74-L133】.  To use this
   feature you need to create an account on Censys, obtain an API
   ID/Secret and install the `censys` package (`pip install
   censys==2.2.12`).

In addition to these API‑based lookups, the script can optionally
invoke `nmap` on the target IP address to perform a service scan
(`nmap -sV -v`).  Nmap must be installed separately on your system for
this feature to work.  Only run nmap scans against systems you own or
are authorised to test.  Unauthorised scanning can be illegal and
violate the terms of service of the target network.

Usage:

    python ipradar.py --ip 8.8.8.8 --whois --shodan --censys --scan

Command‑line arguments:

```
--ip      The target IP address (required).
--whois   Perform an IP whois lookup to find network and location
          information (requires ipwhois).
--shodan  Query Shodan for data about the IP and optionally perform a
          keyword search (requires shodan).  You must set the
          SHODAN_API_KEY environment variable or edit the script to
          provide your API key.
--censys  Retrieve host information from Censys (requires censys).
          You must set CENSYS_API_ID and CENSYS_API_SECRET in your
          environment or edit the script to provide your credentials.
--scan    Run an nmap service scan (nmap -sV -v) against the IP.

```

This tool is intended for educational and authorised network security
research.  Use responsibly.
\n
New in this version:\n
  * **Device discovery by brand** – You can check public exposures of
    popular CCTV, webcam and drone brands via Shodan and Censys.  Use
    the `--device-check` flag along with `--brands` to specify
    comma‑separated vendor names (e.g. `hikvision,dji,d-link`) or rely
    on a built‑in list of common manufacturers.  For each brand the
    script performs a Shodan search using the `product:` filter and a
    Censys search using the `services.software.product` field.  The
    built‑in vendor list has been expanded to cover a wider range of
    CCTV manufacturers (Hikvision, **Dahua**, **Axis**, **Panasonic**, **Bosch**, **Honeywell**),
    consumer webcams (Logitech, **Microsoft**, **Razer**, **HP**, **Lenovo**),
    home security cameras (Arlo, Ring, Blink, Xiaomi, TP‑Link) and
    popular drone makers (DJI, Parrot, Autel, Yuneec, Skydio).  This
    feature provides a high‑level view of how many devices from each
    vendor are exposed on the Internet.  Shodan’s `product` filter is
    particularly useful because it highlights top products such as
    “Hikvision IP Camera,” “TruVision NVR/DVR/IP Camera” and “D‑Link
    DCS‑5020L webcam http interface”【405649198003152†L45-L52】.  A July 2025
    VulnCheck blog post notes that Shodan shows **over one million
    potentially vulnerable Hikvision systems** related to CVE‑2021‑36260【680312211766065†L34-L45】,
    underscoring why discovering exposed CCTV, webcam and drone devices
    matters.
"""

import argparse
import os
import subprocess
import sys
from typing import Optional

def lookup_ip_location(ip: str) -> None:
    """Perform an RDAP whois lookup on the given IP and print location info.

    This function uses the ipwhois.IPWhois class to perform a
    Registration Data Access Protocol (RDAP) query, which returns
    structured information about the IP address.  RDAP is the
    recommended lookup method because it provides more detailed
    network and contact data than legacy whois queries【319599820089173†L3-L7】.

    Parameters
    ----------
    ip : str
        The IP address to look up.
    """
    try:
        from ipwhois import IPWhois
    except ImportError as exc:
        print("ipwhois is not installed. Run 'pip install ipwhois' to use the"
              " whois feature.")
        return
    try:
        obj = IPWhois(ip)
        # RDAP lookup returns a dictionary with fields such as
        # asn_country_code and network.country for country codes【319599820089173†L109-L148】.
        results = obj.lookup_rdap()
    except Exception as err:
        print(f"WHOIS lookup failed: {err}")
        return
    # Extract some basic fields from the RDAP results
    asn = results.get('asn')
    asn_description = results.get('asn_description')
    network_info = results.get('network', {})
    country = network_info.get('country')
    cidr = network_info.get('cidr')
    print("--- IP WHOIS / RDAP Information ---")
    print(f"IP:            {ip}")
    print(f"ASN:           {asn}")
    print(f"ASN Desc:      {asn_description}")
    print(f"Network CIDR:  {cidr}")
    print(f"Country Code:  {country}")
    # Optionally print the registered organisation name if available
    # Entities and objects can be deeply nested; here we look up the first
    # organisation encountered.
    entities = results.get('entities', [])
    objects = results.get('objects', {})
    org_name: Optional[str] = None
    for ent in entities:
        obj_info = objects.get(ent, {})
        roles = obj_info.get('roles', [])
        if 'registrant' in roles or 'registrar' in roles or 'technical' in roles:
            vcard_list = obj_info.get('vcardArray', [])
            # vcardArray is ["vcard", [list of fields]]
            if len(vcard_list) == 2:
                for field in vcard_list[1]:
                    # field is ["name", {}, "text", value]
                    if field[0] == 'fn' and len(field) >= 4:
                        org_name = field[3]
                        break
        if org_name:
            break
    if org_name:
        print(f"Organisation:  {org_name}")
    print()


def search_shodan(ip: str, query: Optional[str] = None, limit: Optional[int] = None) -> None:
    """Query Shodan for the given IP or a keyword search.

    If a query string is provided the function performs a Shodan search
    using the API’s `search` method and prints the IP addresses and
    banners of the results.  Otherwise it will look up the host
    information for the specific IP using `Shodan.host()`【473135104521006†L45-L125】.

    To use this function you need to install the `shodan` library and
    provide your API key via the SHODAN_API_KEY environment variable
    or by editing this script.  Refer to Shodan’s documentation for
    further details【473135104521006†L45-L67】.

    Parameters
    ----------
    ip : str
        Target IP address.  If a query string is supplied this
        parameter is ignored.
    query : Optional[str], default None
        Free‑form search query passed to Shodan.  If None, a host
        lookup is performed instead.
    """
    try:
        import shodan
    except ImportError:
        print("The shodan package is not installed. Run 'pip install shodan' to"
              " use the Shodan feature.")
        return
    api_key = os.environ.get('SHODAN_API_KEY') or 'YOUR_SHODAN_API_KEY'
    if not api_key or api_key == 'YOUR_SHODAN_API_KEY':
        print("Please set your Shodan API key in the SHODAN_API_KEY environment"
              " variable or edit the script.")
        return
    api = shodan.Shodan(api_key)
    try:
        if query:
            print(f"Searching Shodan for query: {query}")
            # Use the limit parameter if provided; otherwise Shodan defaults to
            # 100 results per page.  The limit argument restricts the number
            # of results returned by the API.
            try:
                if limit is not None:
                    results = api.search(query, limit=limit)
                else:
                    results = api.search(query)
            except TypeError:
                # Older versions of shodan library may not support the limit
                # keyword; fall back to default behaviour.
                results = api.search(query)
            total = results.get('total', 0)
            print(f"Results found: {total}")
            for match in results.get('matches', []):
                ip_str = match.get('ip_str')
                data = match.get('data', '').strip()
                print(f"\nIP: {ip_str}\nBanner: {data[:200]}...")
        else:
            print(f"Looking up Shodan host info for {ip}")
            host = api.host(ip)
            print(f"IP: {host.get('ip_str')}")
            print(f"Organisation: {host.get('org', 'N/A')}")
            print(f"Operating System: {host.get('os', 'N/A')}")
            for item in host.get('data', []):
                port = item.get('port')
                banner = item.get('data', '').strip()
                print(f"\nPort: {port}\nBanner: {banner[:200]}...")
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
    except Exception as e:
        print(f"Unexpected error during Shodan lookup: {e}")
    print()


def search_censys(ip: str, query: Optional[str] = None, fields: Optional[list] = None,
                  per_page: int = 5, pages: int = 1) -> None:
    """Query Censys for the given IP or perform a search.

    When a query is provided this function calls `CensysHosts.search()` to
    iterate through matching hosts; otherwise it invokes `CensysHosts.view()`
    to retrieve details for the specified IP【468786160087640†L74-L133】.  The
    Censys Python library requires an API ID and secret which should be
    provided via the environment variables `CENSYS_API_ID` and
    `CENSYS_API_SECRET`, or by editing the script.  See the Censys
    documentation for more information【468786160087640†L74-L133】.

    Parameters
    ----------
    ip : str
        Target IP address.  If a query is supplied this parameter is
        ignored.
    query : Optional[str], default None
        Search query string using Censys search syntax.  Examples:
        ``services.service_name: HTTP`` or ``services.port: 22``.  If
        None, a host lookup is performed.
    fields : Optional[list], default None
        List of fields to return for each result when performing a search.
    """
    try:
        from censys.search import CensysHosts
    except ImportError:
        print("The censys package is not installed. Run 'pip install censys' to"
              " use the Censys feature.")
        return
    api_id = os.environ.get('CENSYS_API_ID') or 'YOUR_CENSYS_API_ID'
    api_secret = os.environ.get('CENSYS_API_SECRET') or 'YOUR_CENSYS_API_SECRET'
    if not api_id or api_id == 'YOUR_CENSYS_API_ID' or not api_secret or api_secret == 'YOUR_CENSYS_API_SECRET':
        print("Please set your Censys API ID and secret in the CENSYS_API_ID and"
              " CENSYS_API_SECRET environment variables or edit the script.")
        return
    try:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        if query:
            print(f"Searching Censys for query: {query}")
            # Use provided per_page and pages values to control pagination.
            search_results = h.search(query, per_page=per_page, pages=pages, fields=fields)
            for page in search_results:
                for host in page:
                    # host is a dict containing the fields requested
                    print(host)
        else:
            print(f"Fetching Censys host view for {ip}")
            host = h.view(ip)
            # Display some key fields
            print(f"IP: {host.get('ip')}")
            location = host.get('location', {})
            print(f"Location Country: {location.get('country')}")
            for svc in host.get('services', []):
                port = svc.get('port')
                service_name = svc.get('service_name')
                extended = svc.get('extended_service_name')
                print(f"\nPort: {port}\nService: {service_name}\nExtended: {extended}")
    except Exception as e:
        print(f"Censys API error: {e}")
    print()


def run_nmap_scan(ip: str) -> None:
    """Run an nmap service/version scan against the IP address.

    The function constructs the command `nmap -sV -v <ip>` and runs it
    using subprocess.  Nmap must be installed on your system for this
    to work.  Only scan hosts that you own or have explicit permission
    to test.  Unauthorised scanning may be illegal.

    Parameters
    ----------
    ip : str
        Target IP address.
    """
    cmd = ["nmap", "-sV", "-v", ip]
    try:
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
    except FileNotFoundError:
        print("nmap command not found. Please install nmap to use the scan feature.")
    except subprocess.CalledProcessError as e:
        print(f"nmap returned an error: {e.stderr}")
    except Exception as e:
        print(f"Unexpected error running nmap: {e}")
    print()


def check_devices(brands: list, shodan_limit: int = 10, censys_pages: int = 1,
                  censys_per_page: int = 5, fields: Optional[list] = None) -> None:
    """Check public exposures of devices by brand using Shodan and Censys.

    For each brand name in the list, this function performs a Shodan
    search using the `product:` filter and a Censys search using the
    `services.software.product` field.  The search limits and
    pagination can be customised.  Results are printed to stdout.

    Parameters
    ----------
    brands : list
        List of vendor or product names to search for.
    shodan_limit : int, default 10
        Maximum number of results to return from Shodan for each
        brand.  Shodan’s API will return up to this many matches.
    censys_pages : int, default 1
        Number of pages to fetch from Censys.  Each page contains
        `censys_per_page` results.
    censys_per_page : int, default 5
        Number of results per page for Censys queries.
    fields : list, optional
        List of fields to request from Censys search results.  If
        None, all available fields are returned.
    """
    if not brands:
        print("No brands provided for device check.")
        return
    for brand in brands:
        # Normalise brand string (strip whitespace)
        brand_str = brand.strip()
        if not brand_str:
            continue
        print(f"\n===== Checking devices for brand: {brand_str} =====")
        shodan_query = f"product:{brand_str}"
        censys_query = f"services.software.product: {brand_str}"
        print(f"Shodan query: {shodan_query}")
        search_shodan(ip="0.0.0.0", query=shodan_query, limit=shodan_limit)
        print(f"Censys query: {censys_query}")
        search_censys(ip="0.0.0.0", query=censys_query, fields=fields,
                      per_page=censys_per_page, pages=censys_pages)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lightweight IP reconnaissance tool")
    parser.add_argument("--ip", required=True, help="Target IP address (required for most operations; ignored for device checks)")
    parser.add_argument("--whois", action="store_true", help="Perform a whois/RDAP lookup")
    parser.add_argument("--shodan", action="store_true", help="Look up IP or search Shodan (use --query)")
    parser.add_argument("--censys", action="store_true", help="Look up IP or search Censys (use --query)")
    parser.add_argument("--scan", action="store_true", help="Run an nmap service scan against the IP")
    parser.add_argument("--query", help="Search query for Shodan/Censys instead of IP lookup")
    parser.add_argument("--fields", nargs="*", help="Fields to request from Censys search results")
    # Device discovery arguments
    parser.add_argument("--device-check", action="store_true",
                        help="Check public exposures of popular CCTV/webcam/drone brands via Shodan and Censys")
    parser.add_argument("--brands", help="Comma‑separated list of vendor names for device check (e.g. hikvision,dji,d-link). If omitted, a default list is used.")
    parser.add_argument("--shodan-limit", type=int, default=10,
                        help="Maximum number of Shodan results per brand for device checks")
    parser.add_argument("--censys-pages", type=int, default=1,
                        help="Number of pages to fetch from Censys per brand for device checks")
    parser.add_argument("--censys-per-page", type=int, default=5,
                        help="Number of results per Censys page for device checks")
    args = parser.parse_args()

    ip = args.ip
    if args.whois:
        lookup_ip_location(ip)
    if args.shodan:
        search_shodan(ip, query=args.query, limit=args.shodan_limit)
    if args.censys:
        search_censys(ip, query=args.query, fields=args.fields,
                      per_page=args.censys_per_page, pages=args.censys_pages)
    if args.scan:
        run_nmap_scan(ip)
    if args.device_check:
        # Determine list of brands: user supplied or default list
        if args.brands:
            brand_list = [b.strip() for b in args.brands.split(',') if b.strip()]
        else:
            # Default list of popular CCTV/webcam/drone vendors.  We include
            # manufacturers of surveillance cameras (Hikvision, Dahua, Axis,
            # Panasonic, Bosch, Honeywell), consumer webcams (Logitech,
            # Microsoft, Razer, HP, Lenovo), smart home security cameras
            # (Arlo, Ring, Blink, Xiaomi, TP‑Link) and drones (DJI, Parrot,
            # Autel, Yuneec, Skydio).  Feel free to override this list via
            # --brands.
            brand_list = [
                "Hikvision", "Dahua", "Axis", "Panasonic", "Bosch", "Honeywell",
                "Logitech", "Microsoft", "Razer", "HP", "Lenovo",
                "Arlo", "Ring", "Blink", "Xiaomi", "TP-Link",
                "DJI", "Parrot", "Autel", "Yuneec", "Skydio"
            ]
        check_devices(brand_list, shodan_limit=args.shodan_limit,
                      censys_pages=args.censys_pages,
                      censys_per_page=args.censys_per_page,
                      fields=args.fields)
    if not any([args.whois, args.shodan, args.censys, args.scan, args.device_check]):
        print("No actions specified. Use --whois, --shodan, --censys, --scan or --device-check.")


if __name__ == "__main__":
    main()