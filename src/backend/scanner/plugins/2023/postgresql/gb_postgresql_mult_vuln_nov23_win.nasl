# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100981");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-10 14:35:49 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 22:15:00 +0000 (Wed, 13 Dec 2023)");

  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 11.x < 11.22, 12.x < 12.17, 13.x < 13.13, 14.x < 14.10, 15.x < 15.5, 16.x < 16.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-5868: Memory disclosure in aggregate function calls

  - CVE-2023-5869: Buffer overrun from integer overflow in array modification

  - CVE-2023-5870: Role pg_cancel_backend can signal certain superuser processes");

  script_tag(name:"affected", value:"PostgreSQL versions 11.x prior to 11.22, 12.x prior to 12.17,
  13.x prior to 13.13, 14.x prior to 14.10, 15.x prior to 15.5 and 16.x prior to 16.1.");

  script_tag(name:"solution", value:"Update to version 11.22, 12.17, 13.13, 14.10, 15.5, 16.1 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-161-155-1410-1313-1217-and-1122-released-2749/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-5868/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-5869/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-5870/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "11.0", test_version_up: "11.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.22", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.0", test_version_up: "12.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.17", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.0", test_version_up: "13.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "14.0", test_version_up: "14.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "15.0", test_version_up: "15.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "15.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "16.0", test_version_up: "16.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "16.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
