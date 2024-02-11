# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114332");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-08 14:04:05 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-0985");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 12.x < 12.18, 13.x < 13.14, 14.x < 14.11, 15.x < 15.6, 16.x < 16.1 Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Late privilege drop in REFRESH MATERIALIZED VIEW CONCURRENTLY in
  PostgreSQL allows an object creator to execute arbitrary SQL functions as the command issuer. The
  command intends to run SQL functions as the owner of the materialized view, enabling safe refresh
  of untrusted materialized views. The victim is a superuser or member of one of the attacker's
  roles. The attack requires luring the victim into running REFRESH MATERIALIZED VIEW CONCURRENTLY
  on the attacker's materialized view. As part of exploiting this vulnerability, the attacker
  creates functions that use CREATE RULE to convert the internally-built temporary table to a view.");

  script_tag(name:"affected", value:"PostgreSQL version 12.x prior to 12.18, 13.x prior to 13.14,
  14.x prior to 14.11 and 15.x prior to 15.6.

  The only known exploit does not work in PostgreSQL 16 and later. For defense in depth, PostgreSQL
  16.2 adds the protections that older branches are using to fix their vulnerability.");

  script_tag(name:"solution", value:"Update to version 12.18, 13.14, 14.11, 15.6 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-162-156-1411-1314-and-1218-released-2807/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-0985/");

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

if( version_in_range_exclusive( version: version, test_version_lo: "12.0", test_version_up: "12.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.18", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.0", test_version_up: "13.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.14", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "14.0", test_version_up: "14.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "15.0", test_version_up: "15.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "15.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
