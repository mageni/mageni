# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127636");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-22 10:30:11 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 16:07:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-48304", "CVE-2023-48306");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 22.2.10.16, 23.x < 23.0.12.11, 24.x <24.0.12.7, 25.x < 25.0.11, 26.x < 26.0.6, 27.x < 27.1.0 Multiple Vulnerabilities (GHSA-8JWV-C8C8-9FR3, GHSA-8F69-F9JG-4X3V)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-48304: An attacker could enable and disable the birthday calendar for any user on the
  same server.

  - CVE-2023-48306: The DNS pin middleware is vulnerable to DNS rebinding allowing an attacker to
  perform SSRF as a final result.");

  script_tag(name:"affected", value:"Nextcloud Server version prior to 22.2.10.16, 23.x prior to
  23.0.12.11, 24.x prior to 24.0.12.7, 25.x prior to 25.0.11, 26.x prior to 26.0.6 and 27.x prior
  to 27.1.0.");

  script_tag(name:"solution", value:"Update to version 22.2.10.16, 23.0.12.11, 24.0.12.7, 25.0.11,
  26.0.6, 27.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-8JWV-C8C8-9FR3");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-8F69-F9JG-4X3V");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "22.2.10.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "22.2.10.16 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "23.0", test_version_up: "23.0.12.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "23.0.12.11 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "24.0", test_version_up: "24.0.12.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.12.7 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "26.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
