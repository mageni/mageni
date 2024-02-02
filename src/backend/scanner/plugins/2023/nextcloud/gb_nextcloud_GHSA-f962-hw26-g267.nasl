# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127633");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-22 08:53:11 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 02:32:00 +0000 (Wed, 29 Nov 2023)");

  script_cve_id("CVE-2023-48239");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 20.0.14.16, 21.x < 21.0.9.13, 22.x < 22.2.10.15, 23.x < 23.0.12.12, 24.x < 24.0.12.8, 25.x < 25.0.13, 26.x < 26.0.8, 27.x < 27.1.3 Improper Access Control Vulnerability (GHSA-f962-hw26-g267)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious user could update any personal or global external
  storage, making them inaccessible for everyone else as well.");

  script_tag(name:"affected", value:"Nextcloud Server version prior to 20.0.14.16, 21.x prior to
  21.0.9.13, 22.x prior to 22.2.10.15, 23.x prior to 23.0.12.12, 24.x prior to 24.0.12.8, 25.x
  prior to 25.0.13, 26.x prior to 26.0.8 and 27.x prior to 27.1.3.");

  script_tag(name:"solution", value:"Update to version 20.0.14.16, 21.0.9.13, 22.2.10.15,
  23.0.12.12, 24.0.12.8, 25.0.13, 26.0.8, 27.1.3 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-f962-hw26-g267");

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

if( version_is_less( version: version, test_version: "20.0.14.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "20.0.14.16 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "21.0", test_version_up: "21.0.9.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "21.0.9.13 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "22.0", test_version_up: "22.2.10.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "22.2.10.15 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "23.0", test_version_up: "23.0.12.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "23.0.12.12 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "24.0", test_version_up: "24.0.12.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.12.8 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "26.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
