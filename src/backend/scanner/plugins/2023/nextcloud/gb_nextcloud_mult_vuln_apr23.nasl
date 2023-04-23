# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127381");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 13:44:52 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-26482", "CVE-2023-28833", "CVE-2023-28834", "CVE-2023-28835");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 24.x < 24.0.10, 25.x < 25.0.4 Multiple Vulnerabilities (GHSA-h3c9-cmh8-7qpj, GHSA-ch7f-px7m-hg25, GHSA-5w64-6c42-rgcv, GHSA-7w2p-rp9m-9xp9)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-26482: A missing scope validation allow users to create workflows which are designed
  to be only available for administrators.

  - CVE-2023-28833: An admin can upload files with a provided file name into the appdata directory.

  - CVE-2023-28834: A user can get the full data directory path of the Nextcloud server from
  an API endpoint.

  - CVE-2023-28835: Insecure randomness for default password in file sharing when password policy
  app is disabled.");

  script_tag(name:"affected", value:"Nextcloud Server version 24.x prior to 24.0.10 and
  version 25.x prior to 25.0.4.");

  script_tag(name:"solution", value:"Update to version 24.0.10, 25.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-h3c9-cmh8-7qpj");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-ch7f-px7m-hg25");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5w64-6c42-rgcv");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-7w2p-rp9m-9xp9");

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

if( version_in_range_exclusive( version: version, test_version_lo: "24.0.0", test_version_up: "24.0.10" ) ) {
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
