# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124449");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-24 08:10:42 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 14:35:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-5543", "CVE-2023-5546");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.0.x < 4.0.11, 4.1.x < 4.1.6, 4.2.x < 4.2.3 Multiple Vulnerabilities (MSA-23-0035, MSA-23-0038)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-5543 / MSA-23-0035: When duplicating a BigBlueButton activity, the original meeting ID
   was also duplicated instead of using a new ID for the new activity. This could provide
   unintended access to the original meeting.

  - CVE-2023-5546 / MSA-23-0038: ID numbers displayed in the quiz grading report required
  additional sanitizing to prevent a stored XSS risk.");

  script_tag(name:"affected", value:"Moodle versions 4.0.x prior to 4.0.11, 4.1.x prior to 4.1.6
  and 4.2 prior to 4.2.3");

  script_tag(name:"solution", value:"Update to version 4.0.11, 4.1.6, 4.2.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451584");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=451587");

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

if ( version_in_range_exclusive( version: version, test_version_lo: "4.0", test_version_up: "4.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "4.1", test_version_up: "4.1.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if ( version_in_range_exclusive( version: version, test_version_lo: "4.2", test_version_up: "4.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
