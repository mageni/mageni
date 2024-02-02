# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148990");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-12-06 04:05:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 20:05:00 +0000 (Tue, 06 Dec 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-46169", "CVE-2022-48538");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.23 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-46169: A command injection vulnerability allows an unauthenticated user to execute
  arbitrary code on a server running Cacti, if a specific data source was selected for any monitored
  device.

  - CVE-2022-48538: Authentication bypass in the web login functionality because of improper
  validation in the PHP code: cacti_ldap_auth() allows a zero as the password.");

  script_tag(name:"impact", value:"This command injection vulnerability allows an unauthenticated
  user to execute arbitrary commands if a poller_item with the action type POLLER_ACTION_SCRIPT_PHP
  is configured.");

  script_tag(name:"affected", value:"Cacti version 1.2.22 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.23 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf");
  script_xref(name:"URL", value:"https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/");
  script_xref(name:"URL", value:"https://censys.io/cve-2022-46169-cacti/");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/5189");
  script_xref(name:"URL", value:"https://docs.cacti.net/Settings-Auth-LDAP.md");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/commit/9b53889c340031be67b62006a516e847b3793dcb");

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

if (version_is_less(version: version, test_version: "1.2.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
