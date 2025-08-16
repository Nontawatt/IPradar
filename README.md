# IPradar

**IPradar** is a small Python script for basic reconnaissance of IP
addresses.  It combines three open OSINT services—IP whois/RDAP,
Shodan and Censys—and provides an optional integration with `nmap`
for service/version detection.  The script is intended for security
practitioners to perform authorised research on their own
infrastructure.

## Features

* **Whois/RDAP lookup** – Uses the [`ipwhois` library](https://ipwhois.readthedocs.io/en/latest/README.html) to perform an RDAP
  query.  RDAP is the modern whois protocol and returns structured
  information about the IP’s network assignment and autonomous system.
  According to the documentation, RDAP provides a far better data
  structure and richer network and contact information than legacy
  whois【319599820089173†L3-L7】.  The script extracts the ASN, network
  CIDR and country code from the response.

* **Shodan search** – Integrates with the official
  [Shodan Python library](https://shodan.readthedocs.io/en/latest/tutorial.html).  Shodan’s API allows you to
  initialise an API client with your key and perform searches or host
  lookups via `api.search()` and `api.host()`【473135104521006†L45-L67】.  IPradar can
  perform a free‑form Shodan search (for example, `"http.title:\"drone
  command\""`) or retrieve banners and services for a specific IP.

* **Censys search** – Uses the
  [Censys Python client](https://censys-python.readthedocs.io/en/v2.2.12/usage-v2.html) to query the hosts index.  The
  `CensysHosts` class provides `search()` and `view()` functions to
  retrieve host information【468786160087640†L74-L133】.  The script can either run a
  query (e.g. `services.service_name: MQTT`) or fetch detailed host
  data for a specific IP.  Results include the ports, service names
  and location data.

* **Nmap integration** – Optionally executes `nmap -sV -v <ip>` via
  `subprocess`.  This runs a service/version scan on the target IP to
  enumerate open ports and detect the software running on them.  You
  must have [nmap](https://nmap.org) installed on your system for this
  feature to work.  Only scan systems that you own or have explicit
  permission to test.

* **Device discovery by brand** – IPradar can perform brand‑based
  searches for publicly exposed **CCTV cameras**, **consumer webcams**
  and **drones**.  Use the `--device-check` flag with `--brands` to
  specify comma‑separated vendor names, or rely on a built‑in set of
  well‑known manufacturers.  The built‑in list has been expanded to
  cover major CCTV vendors (**Hikvision**, **Dahua**, **Axis**, **Panasonic**,
  **Bosch**, **Honeywell**), consumer webcam makers (**Logitech**, **Microsoft**,
  **Razer**, **HP**, **Lenovo**), smart home security cameras (**Arlo**, **Ring**, **Blink**, **Xiaomi**, **TP‑Link**) and popular drone brands (**DJI**, **Parrot**, **Autel**, **Yuneec**, **Skydio**).  For each
  brand the script runs a **Shodan** search using the `product:` filter and a
  **Censys** search using `services.software.product`.  Shodan’s product filter
  surfaces top products like “Hikvision IP Camera,” “TruVision NVR/DVR/IP
  Camera” and “D‑Link DCS‑5020L webcam http interface”【405649198003152†L45-L52】.
  A **VulnCheck** report published in July 2025 noted that Shodan showed **over
  one million potentially vulnerable Hikvision systems** related to
  CVE‑2021‑36260【680312211766065†L34-L45】, illustrating why identifying
  exposed CCTV, webcam and drone devices is important.  This feature
  provides a high‑level overview of how many devices from each vendor are
  reachable on the Internet.

## Installation

1. Install Python 3.8 or newer.
2. Clone this repository or download `ipradar.py` and `README.md`.
3. Install the optional dependencies depending on which features you
   want to use:

   ```sh
   pip install ipwhois        # for whois/RDAP lookups
   pip install shodan         # for Shodan API queries
   pip install censys==2.2.12 # for Censys API queries
   ```

4. (Optional) Install `nmap` on your system if you plan to use the
   scanning feature.

5. Set your API credentials as environment variables:

   ```sh
   export SHODAN_API_KEY=<your-shodan-key>
   export CENSYS_API_ID=<your-censys-id>
   export CENSYS_API_SECRET=<your-censys-secret>
   ```

## Usage

Run the script with the target IP and select the features you need.  For
example, to perform all available lookups on IP `8.8.8.8`:

```sh
python ipradar.py --ip 8.8.8.8 --whois --shodan --censys --scan
```

### Options

| Option      | Description                                                          |
|-------------|----------------------------------------------------------------------|
| `--ip`      | Target IP address (required).                                        |
| `--whois`   | Perform an RDAP whois lookup (requires `ipwhois`).                   |
| `--shodan`  | Query Shodan API (requires `shodan`; needs `SHODAN_API_KEY`).         |
| `--censys`  | Query Censys API (requires `censys`; needs `CENSYS_API_ID/SECRET`).    |
| `--scan`    | Run `nmap -sV -v` against the target (requires `nmap`).               |
| `--query`   | When used with `--shodan` or `--censys`, performs a search query instead of a host lookup. |
| `--fields`  | List of fields to request from Censys search results (default: all).   |
| `--device-check` | Search for public devices by brand using Shodan and Censys. |
| `--brands` | Comma‑separated vendor names for device check (default list of common CCTV/webcam/drone brands). |
| `--shodan-limit` | Maximum number of Shodan results per brand when `--device-check` is enabled (default: 10). |
| `--censys-pages` | Number of pages to fetch from Censys per brand (default: 1). |
| `--censys-per-page` | Number of results per Censys page (default: 5). |

### Examples

* Look up the location and ASN for an IP:

  ```sh
  python ipradar.py --ip 1.1.1.1 --whois
  ```

* Search Shodan for hosts with “drone” in the HTTP title:

  ```sh
  python ipradar.py --ip 0.0.0.0 --shodan --query "http.title:\"drone command\""
  ```

* Perform a Censys search for devices running an MQTT service and list their IPs and ports:

  ```sh
  python ipradar.py --ip 0.0.0.0 --censys --query "services.service_name: MQTT" --fields ip services.port services.service_name
  ```

* Run an nmap service scan:

  ```sh
  python ipradar.py --ip 192.0.2.10 --scan
  ```

* Check exposures for a list of device brands:

  ```sh
  python ipradar.py --ip 0.0.0.0 --device-check \
    --brands hikvision,dahua,logitech,dji \
    --shodan-limit 5 --censys-pages 1 --censys-per-page 3
  ```

  This command queries Shodan and Censys for devices manufactured by
  **Hikvision**, **Dahua**, **Logitech** and **DJI**.  It retrieves up to five
  results from Shodan and three results from Censys per brand.  You can omit
  `--brands` to use the expanded default list of CCTV, webcam and drone
  vendors.

## Legal and Ethical Notice

This tool is intended for lawful use.  You must only query
services and scan systems that you own or are explicitly authorised to
test.  Unauthorised reconnaissance or port scanning may violate
applicable laws and the terms of service of Shodan and Censys.  The
developer of this script takes no responsibility for misuse.  For
background on the libraries used, see the official documentation for
the `ipwhois` package【203691511594537†L8-L10】, the Shodan Python API
【473135104521006†L45-L67】 and the Censys Python client【468786160087640†L74-L133】.