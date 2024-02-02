# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127634");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-22 09:30:11 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 15:13:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-48301", "CVE-2023-48302");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 25.0.13, 26.x < 26.0.8, 27.x < 27.1.3 Multiple XSS Vulnerabilities (GHSA-wgpw-qqq2-gwv6, GHSA-p7g9-x25m-4h87)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following Vulnerabilities exist:

  - CVE-2023-48301: An attacker could insert links into circles name that would be opened when
  clicking the circle name in a search filter.

  - CVE-2023-48302: When a user is tricked into copy pasting HTML code without markup
  (Ctrl+Shift+V) the markup will actually render.");

  script_tag(name:"affected", value:"Nextcloud Server version prior to 25.0.13, 26.x prior to
  26.0.8 and 27.x prior to 27.1.3.");

  script_tag(name:"solution", value:"Update to version 25.0.13, 26.0.8, 27.1.3 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-wgpw-qqq2-gwv6");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-p7g9-x25m-4h87");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "25.0.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "26.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
