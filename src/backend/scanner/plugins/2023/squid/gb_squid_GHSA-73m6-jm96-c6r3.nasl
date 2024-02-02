# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151251");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  # nb: This was initially a single VT which got split into multiple later. As we covered all flaws
  # at this time the original creation_date has been kept in all later created VTs.
  script_tag(name:"creation_date", value:"2023-10-20 08:47:30 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 15:07:00 +0000 (Thu, 09 Nov 2023)");

  script_cve_id("CVE-2023-46724");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid DoS Vulnerability (GHSA-73m6-jm96-c6r3, SQUID-2023:4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability in
  the SSL Certificate validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an Improper Validation of Specified Index bug Squid is
  vulnerable to a Denial of Service attack against SSL Certificate validation.

  This flaw was part of the 'Squid Caching Proxy Security Audit: 55 vulnerabilities and 35 0days'
  publication in October 2023.");

  script_tag(name:"affected", value:"Squid version 3.3.0.1 through 6.3.");

  script_tag(name:"solution", value:"Update to version 6.4 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-73m6-jm96-c6r3");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/");
  script_xref(name:"URL", value:"https://joshua.hu/squid-security-audit-35-0days-45-exploits");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/11/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.3.0.1", test_version_up: "6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
