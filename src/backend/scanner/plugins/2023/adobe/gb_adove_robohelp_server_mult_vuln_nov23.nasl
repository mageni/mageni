# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126565");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-20 12:09:13 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 17:44:00 +0000 (Wed, 22 Nov 2023)");

  script_cve_id("CVE-2023-22268", "CVE-2023-22272", "CVE-2023-22273", "CVE-2023-22274",
                "CVE-2023-22275");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe RoboHelp Server < 11.5 Multiple Vulnerabilities (APSB23-53)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_server_http_detect.nasl", "gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_mandatory_keys("adobe/robohelp/server/detected");

  script_tag(name:"summary", value:"Adobe RoboHelp Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-22268: Improper neutralization of special elements used in an SQL Command
  (SQL Injection) could lead to an information disclosure by an low-privileged authenticated
  attacker.

  - CVE-2023-22272: Improper input validation could lead to an information disclosure by an
  unauthenticated attacker

  - CVE-2023-22273: Improper limitation of a pathname to a restricted directory (Path Traversal)
  could lead to a remote code execution by an admin authenticated attacker.

  - CVE-2023-22274: Restriction of XML external entity reference (XXE) could lead to an information
  disclosure by an unauthenticated attacker.

  - CVE-2023-22275: Improper neutralization of special elements used in an SQL Command
  (SQL Injection) could lead to an information disclosure by an unauthenticated attacker.");

  script_tag(name:"affected", value:"Adobe RoboHelp Server prior to version 11.5.");

  script_tag(name:"solution", value:"Update to version 11.5 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp-server/apsb23-53.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "11.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
