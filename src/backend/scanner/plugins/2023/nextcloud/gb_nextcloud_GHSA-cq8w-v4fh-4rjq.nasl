# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118529");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 13:55:12 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"1.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:P/I:N/A:N");

  script_cve_id("CVE-2023-39952");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Improper Access Control Vulnerability (GHSA-cq8w-v4fh-4rjq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user can access files inside a subfolder of a groupfolder
  accessible to them, even if advanced permissions would block access to the subfolder.");

  script_tag(name:"affected", value:"Nextcloud Server versions 25.x prior to 25.0.8, 26.x
  prior to 26.0.3 and 27.x prior to 27.0.1.");

  script_tag(name:"solution", value:"Update to version 25.0.8, 26.0.3, 27.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-cq8w-v4fh-4rjq");

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

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
