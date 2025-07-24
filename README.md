# DNS Leak Checker 
A simple yet powerful Bash script to discover internal IP addresses and suspicious cloud assets that are inadvertently exposed through public DNS records. This tool automates the process of running an OWASP Amass scan and parsing the results to highlight potential security misconfigurations.

DNS Leak Checker assists in guarding against MITRE ATT&CK TA0043 – Reconnaissance, specifically: 
T1596 - Search Open Technical Databases 
T1595.002 - Active Scanning: DNS 
T1590.002 - Gather Victim Network Info: DNS

---

## Features

* **Flexible Scanning**: Scan a single domain, a list of domains from a file, or analyze a pre-existing Amass output file.

* **Leak Detection**:

  * Identifies **internal IP addresses** (RFC1918) exposed in A/AAAA records.

  * Flags **suspicious CNAME records** pointing to internal-facing cloud resources (e.g., internal ELBs).

  * Reports on the use of **wildcard (*) subdomains**.

* **Automated Tooling**: Automatically checks for and offers to install/upgrade Amass to the latest version.

* **Rich Reporting**:

  * Generates a detailed Markdown (.md) report by default.

  * Optionally exports to JSON, CSV, and HTML (if pandoc is installed).

* **Customizable**: Use an allowlist to ignore known, safe CNAMEs and reduce noise.

---

## Compatibility

This script is designed to run on Unix-like operating systems.

**Supported**:

Linux (Debian, Ubuntu, CentOS, RHEL, etc.)

macOS (using Homebrew for package management)

**Not Supported**:

Windows (Native) using Command Prompt or PowerShell.

*Note for Windows Users: You can run this script perfectly on Windows by using the Windows Subsystem for Linux (WSL), which provides a full Linux environment inside Windows.*

---

## Prerequisites & Installation

**Prerequisites**
You'll need the following tools installed:

`jq`: For processing JSON data.

macOS: `brew install jq`

Debian/Ubuntu: `sudo apt-get install jq`

CentOS/RHEL: `sudo yum install jq`

`amass`: The script will try to install this for you using brew on macOS or from GitHub releases on Linux.

`pandoc` (Optional): Required only for generating the .html report.

**Installation**
1. Clone the repository:

``` Bash

git clone https://github.com/your-username/dns-leak-checker.git
cd dns-leak-checker

```

2. Make the script executable:

``` Bash

chmod +x dns-leak-checker.sh

```

---

## Usage

The script can be run in three primary modes. All reports are saved to the `dns-leak-checker-output/` directory.

**Scan a Single Domain**

This will run a live Amass scan, save the full colored output to `dns-leak-checker-output/example.amass.txt`, and then generate the reports.

``` Bash

./dns-leak-checker.sh --domain example.com --export-json --export-csv --verbose

```

**Scan a List of Domains**

Provide a text file with one domain per line. The script will scan each domain sequentially.

``` Bash

./dns-leak-checker.sh --domain-list domains.txt

```

**Analyze an Existing Amass File**

If you already have a detailed Amass text output file, you can parse it directly.

``` Bash

./dns-leak-checker.sh --input-amass /path/to/amass-output.txt --output-prefix my-report

```

*Note: A Markdown (`.md`) report is created by default for every scan. For live scans, a full Amass text log (`.amass.txt`) is also saved. Use the flags below for additional formats.*

---

**Command-Line Options**

|Flag             |Argument	     |Description
|:--------------- |:-------------|:----------------------------------------------------------------|
|`--domain`	      |`example.com` |Scan a single domain.
|`--domain-list`  |`domains.txt` |Scan a list of domains from a file.
|`--input-amass`  |`amass.txt`	 |Parse a pre-existing detailed Amass output file.
|`--output-prefix`|`<name>`	     |A prefix for all output report files. Defaults to the domain name.
|`--export-json`	|(none)	       |Generate a JSON report.
|`--export-csv`   |(none)	       |Generate a CSV report.
|`--upgrade-amass`|(none)	       |Force an upgrade of Amass before scanning.
|`--verbose`	    |(none)	       |Enable verbose logging output.
|`--log-file`	    |`<file>`	     |Tee all console output to a log file.
|`--help`         |(none)	       |Show the help message.

---

## Example Output

**Terminal Summary**

After a scan, a summary is printed to the console:

|Summary               |   |
|:---------------------|:--|
|Internal IP leaks     |4  |
|Suspicious CNAMEs     |2  |
|Wildcard subdomains   |0  |
|Total affected assets |6  |

**JSON Report** (`.json`)
A structured report with distinct fields, perfect for automation.

``` JSON

{
  "internal_leaks": [
    {
      "subdomain": "internal-prd-app.example.com",
      "ip_address": "10.0.30.104"
    }
  ],
  "cname_leaks": [
    {
      "subdomain": "manage.example.com",
      "target": "internal-prd-elb.eu-west-1.elb.amazonaws.com"
    }
  ],
  "wildcard_leaks": []
}

```

**Markdown Report** (`.md`)

A clean, human-readable report with tables.

``` Markdown

# DNS Leak Report – charlie

## Internal IP leaks (4)

| Subdomain | IP Address |
|---|---|
| `internal-prd-app...` | `10.0.30.104` |
| `internal-prd-app...` | `10.0.32.27` |
| `internal-stg-app...` | `10.0.130.101` |
| `internal-stg-app...` | `10.0.132.59` |

## Suspicious CNAMEs (2)

| Subdomain | CNAME Target |
|---|---|
| `manage-stg.charlie.com` | `internal-stg-app...` |
| `manage.charlie.com` | `internal-prd-app...` |

## Wildcard subdomains (0)

```
---

## Customization: CNAME Allowlist

To reduce noise and prevent false positives, you can create a file named `allowlist_cnames.txt` in the same directory as the script. Add any CNAME target domains that you consider safe, one per line. The script will automatically ignore any findings that point to a domain in this list.

**Example** `allowlist_cnames.txt`:

```
safe-third-party.example.com
another-known-provider.net

```

---

## License

This project is licensed under the MIT License.
