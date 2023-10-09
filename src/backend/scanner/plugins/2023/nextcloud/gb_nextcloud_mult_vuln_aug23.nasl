# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118528");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 13:55:12 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2023-39958", "CVE-2023-39959", "CVE-2023-39961", "CVE-2023-39962",
                "CVE-2023-39963");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (GHSA-vv27-g2hq-v48h, GHSA-g97r-8ffm-hfpj, GHSA-qhgm-w4gx-gvgp, GHSA-xwxx-2752-w3xm, GHSA-j4qm-5q5x-54m5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-39958: Missing brute force protection on OAuth2 API controller

  - CVE-2023-39959: Existence of calendars and addressbooks can be checked by unauthenticated users

  - CVE-2023-39961: Text does not respect 'Allow download' permissions

  - CVE-2023-39962: Users can delete external storage mount points

  - CVE-2023-39963: Missing password confirmation when creating app passwords.");

  script_tag(name:"affected", value:"Nextcloud Server versions 25.x prior to 25.0.9, 26.x prior
  to 26.0.4 and 27.x prior to 27.0.1.");

  script_tag(name:"solution", value:"Update to version 25.0.9, 26.0.4, 27.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-vv27-g2hq-v48h");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-g97r-8ffm-hfpj");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qhgm-w4gx-gvgp");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-xwxx-2752-w3xm");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-j4qm-5q5x-54m5");

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

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.4" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.0.1" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
