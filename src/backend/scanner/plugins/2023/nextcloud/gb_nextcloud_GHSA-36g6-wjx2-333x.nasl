# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127371");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 07:53:11 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-25820");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 24.0.x < 24.0.10, 25.0.x < 25.0.4 Missing Brute Force Protection Vulnerability (GHSA-36g6-wjx2-333x)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a missing brute force
  protection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When an attacker gets access to an already logged in user
  session they can then brute force the password on the confirmation endpoint.");

  script_tag(name:"affected", value:"Nextcloud Server versions 24.0.x prior to 24.0.10 and 25.0.x
  prior to 25.0.4.");

  script_tag(name:"solution", value:"Update to version 24.0.10, 25.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-36g6-wjx2-333x");

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

if( version_in_range_exclusive( version: version, test_version_lo: "24.0.0", test_version_up: "24.0.10") ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0.0", test_version_up: "25.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
