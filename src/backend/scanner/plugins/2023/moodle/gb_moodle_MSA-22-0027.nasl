# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127374");
  script_version("2023-03-29T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-03-29 10:10:12 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-27 13:31:42 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-40208");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.16 3.11.x < 3.11.9, 4.0.x < 4.0.3 Quiz Sequential Navigation Bypass Vulnerability (MSA-22-0027)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a quiz sequential navigation bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient limitations in some quiz web services made it
  possible for students to bypass sequential navigation during a quiz attempt.");

  script_tag(name:"affected", value:"Moodle version prior to 3.9.16, 3.11.x prior to 3.11.9 and
  4.0.x prior to 4.0.3.");

  script_tag(name:"solution", value:"Update to version 3.9.16, 3.11.9, 4.0.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438761");

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

if( version_is_less( version: version, test_version: "3.9.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.16" );
  security_message( port: port, data: report );
  exit( 0 );
}


if( version_in_range_exclusive( version: version, test_version_lo: "3.11.0", test_version_up: "3.11.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.11.9" );
  security_message( port: port, data: report );
  exit( 0 );
}


if( version_in_range_exclusive( version: version, test_version_lo: "4.0.0", test_version_up: "4.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
