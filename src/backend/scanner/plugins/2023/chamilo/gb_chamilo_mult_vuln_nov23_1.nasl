# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126552");
  script_version("2023-12-07T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-01 11:47:25 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 18:50:00 +0000 (Mon, 04 Dec 2023)");

  script_cve_id("CVE-2023-3368", "CVE-2023-3533", "CVE-2023-3545");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS 1.11.x < 1.11.22 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-3368: Unauthenticated attackers are able to execute commands on the server under
  the permissions of the web server.

  - CVE-2023-3533: Unauthenticated attackers are able to perform stored cross-site scripting
  (XSS) attacks and obtain remote code execution via arbitrary file write.

  - CVE-2023-3545: Unauthenticated attackers are able to bypass file upload security
  protections and obtain remote code execution (RCE) via uploading of '.htaccess' file.");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x prior to 1.11.22.");

  script_tag(name:"solution", value:"Update to version 1.11.22 or later");

  script_xref(name:"URL", value:"https://11.chamilo.org/documentation/changelog.html#1.11.22");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-121-2023-07-05-Critical-impact-High-risk-Unauthenticated-Command-Injection-CVE-2023-3368");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-124-2023-07-13-Critical-impact-High-risk-Unauthenticated-Arbitrary-File-Write-RCE-CVE-2023-3533");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/security_issues#Issue-125-2023-07-13-Critical-impact-Moderate-risk-Htaccess-File-Upload-Security-Bypass-on-Windows-CVE-2023-3545");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11.22", install_path: location);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
