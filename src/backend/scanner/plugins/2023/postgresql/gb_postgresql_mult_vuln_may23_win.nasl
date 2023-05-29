# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104743");
  script_version("2023-05-12T10:50:26+0000");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-12 08:24:51 +0000 (Fri, 12 May 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-2454", "CVE-2023-2455");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 11.x < 11.20, 12.x < 12.15, 13.x < 13.11, 14.x < 14.8, 15.x < 15.3 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-2454: 'CREATE SCHEMA ... schema_element' defeats protective search_path changes

  - CVE-2023-2455: Row security policies disregard user ID changes after inlining");

  script_tag(name:"affected", value:"PostgreSQL versions 11.x prior to 11.20, 12.x prior to 12.15,
  13.x prior to 13.11, 14.x prior to 14.8 and 15.x prior to 15.3.");

  script_tag(name:"solution", value:"Update to version 11.20, 12.15, 13.11, 14.8, 15.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-153-148-1311-1215-and-1120-released-2637/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-2454/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-2455/");

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

if( version_in_range_exclusive( version: version, test_version_lo: "11.0", test_version_up: "11.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "11.20", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "12.0", test_version_up: "12.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.0", test_version_up: "13.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "14.0", test_version_up: "14.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "15.0", test_version_up: "15.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "15.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
