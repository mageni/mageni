# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:axis_os";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170612");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-20 11:26:59 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 20:19:00 +0000 (Thu, 19 Oct 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-21415");

  script_name("AXIS OS Path Traversal Vulnerability (Oct 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS OS is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The VAPIX API overlay_del.cgi was vulnerable to path traversal
  attacks that allows for file deletion.");

  script_tag(name:"affected", value:"AXIS OS version prior to 6.50.5.14, 7.x, 8.x prior to 8.40.35,
  9.x prior to 9.80.47, 10.x prior to 10.12.206 and 11.x prior to 11.6.94.");

  script_tag(name:"solution", value:"Update to version 6.50.5.14, 8.40.35, 9.80.47, 10.12.206,
  11.6.94 or later.");

  script_xref(name:"URL", value:"https://www.axis.com/dam/public/b6/55/e2/cve-2023-21415pdf-en-US-416245.pdf");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "6.50.5.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.50.5.14" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.0.0", test_version_up: "8.40.35" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.40.35" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.0.0", test_version_up: "9.80.47" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.80.47" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "10.0.0", test_version_up: "10.12.206" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.12.206" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "11.0.0", test_version_up: "11.6.94" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.6.94" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );