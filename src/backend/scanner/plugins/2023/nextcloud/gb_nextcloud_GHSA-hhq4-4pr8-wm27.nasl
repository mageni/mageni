# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127380");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 07:44:52 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-28643");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 24.x < 24.0.9, 25.x < 25.0.3 Incorrectly-Resolved Name or Reference Vulnerability (GHSA-hhq4-4pr8-wm27)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an incorrectly-resolved name
  or reference vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"When a recipient receives 2 shares with the same name, and
  memory cache is configured, the second share will replace the first one instead
  of being renamed to (2).");

  script_tag(name:"affected", value:"Nextcloud Server version 24.x prior to 24.0.9 and
  version 25.x prior to 25.0.3.");

  script_tag(name:"solution", value:"Update to version 24.0.9, 25.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-hhq4-4pr8-wm27");

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

if( version_in_range_exclusive( version: version, test_version_lo: "24.0.0", test_version_up: "24.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0.0", test_version_up: "25.0.3" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
