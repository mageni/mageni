# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126433");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-23 08:00:52 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2023-32320", "CVE-2023-35172", "CVE-2023-35927", "CVE-2023-35928");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 25.x < 25.0.7, 26.x < 26.0.2 Multiple Vulnerabilities (GHSA-qphh-6xh7-vffg, GHSA-mjf5-p765-qmr6, GHSA-h7f7-535f-7q87, GHSA-637g-xp2c-qh5h)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-32320: Brute force protection allows to send more requests than intended.

  - CVE-2023-35172: Password reset endpoint is not brute force protected.

  - CVE-2023-35927: System addressbooks can be modified by malicious trusted server.

  - CVE-2023-35928: User scoped external storage can be used to gather credentials of other user.");

  script_tag(name:"affected", value:"Nextcloud Server versions 25.x prior to 25.0.7 and 26.x prior
  to 26.0.2.");

  script_tag(name:"solution", value:"Update to version 25.0.7, 26.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qphh-6xh7-vffg");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-mjf5-p765-qmr6");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-h7f7-535f-7q87");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-637g-xp2c-qh5h");

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

if( version_in_range_exclusive( version: version, test_version_lo: "25.0.0", test_version_up: "25.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0.0", test_version_up: "26.0.2" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
