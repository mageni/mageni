# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127379");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-03-31 11:44:52 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2023-28844");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 24.0.4 < 24.0.10, 25.x < 25.0.4 Improper Access Control Vulnerability (GHSA-w47p-f66h-h2vj)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Users that should not be able to download a file can still
  download an older version and use that for uncontrolled distribution.");

  script_tag(name:"affected", value:"Nextcloud Server version 24.0.4 prior to 24.0.10 and
  version 25.x prior to 25.0.4.");

  script_tag(name:"solution", value:"Update to version 24.0.10, 25.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-w47p-f66h-h2vj");

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

if( version_in_range_exclusive( version: version, test_version_lo: "24.0.4", test_version_up: "24.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0.0", test_version_up: "25.0.4" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
