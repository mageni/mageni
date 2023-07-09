# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126416");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-22 10:10:42 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-35132", "CVE-2023-35133");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (MSA-23-0017, MSA-23-0018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-23-0017 / CVE-2023-35132: Minor SQL injection risk on Mnet SSO access control page

  - MSA-23-0018 / CVE-2023-35133: SSRF risk due to insufficient check on the cURL blocked hosts
  list");

  script_tag(name:"affected", value:"Moodle versions 3.9 through 3.9.21, 3.11 through 3.11.14,
  4.0 through 4.0.8, 4.1 through 4.1.3 and 4.2 prior to 4.2.1");

  script_tag(name:"solution", value:"Update to version 3.9.22, 3.11.15, 4.0.9, 4.1.4, 4.2.1 or
  later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=447830");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=447831");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_in_range( version: version, test_version: "3.9.0", test_version2: "3.9.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.22", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range( version: version, test_version: "3.11.0", test_version2: "3.11.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.11.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range( version: version, test_version: "4.0", test_version2: "4.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range( version: version, test_version: "4.1", test_version2: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "4.2", test_version_up: "4.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
