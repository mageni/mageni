# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127420");
  script_version("2023-05-05T16:07:24+0000");
  script_tag(name:"last_modification", value:"2023-05-05 16:07:24 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-04 13:40:17 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-30944");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.21, 3.11.x < 3.11.14, 4.0.x < 4.0.8, 4.1.x < 4.1.3 SQLi Vulnerability (MSA-23-0015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A limited SQL injection risk in functionality used by the Wiki
  activity when listing pages.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.21, 3.11.x prior to 3.11.14,
  4.0.x prior to 4.0.8 and 4.1.x prior to 4.1.3.");

  script_tag(name:"solution", value:"Update to version 3.9.21, 3.11.14, 4.0.8, 4.1.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=446286");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.9.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.21", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.11", test_version_up: "3.11.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.11.14", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.0", test_version_up: "4.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1", test_version_up: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
