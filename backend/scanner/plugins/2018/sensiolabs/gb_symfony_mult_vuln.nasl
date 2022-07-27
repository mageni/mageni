###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symfony_mult_vuln.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Sensiolabs Symfony <= 2.7.48, 2.8.* <= 2.8.43, 3.* <= 3.3.17, 3.4.* <= 3.4.13, 4.0.* <= 4.0.13 and 4.1.* <= 4.1.2 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112350");
  script_version("$Revision: 12068 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-06 14:47:22 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14773", "CVE-2018-14774");

  script_name("Sensiolabs Symfony <= 2.7.48, 2.8.* <= 2.8.43, 3.* <= 3.3.17, 3.4.* <= 3.4.13, 4.0.* <= 4.0.13 and 4.1.* <= 4.1.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"This host runs Symfony and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Support for a (legacy) IIS header that lets users override the path in the request URL via the X-Original-URL
  or X-Rewrite-URL HTTP request header allows a user to access one URL but have Symfony return a different one
  which can bypass restrictions on higher level caches and web servers. (CVE-2018-14773)

  - When using HttpCache, the values of the X-Forwarded-Host headers are implicitly and wrongly set as trusted,
  leading to potential host header injection. (CVE-2018-14774)");
  script_tag(name:"affected", value:"Symfony versions 2.7.0 to 2.7.48, 2.8.0 to 2.8.43, 3.3.0 to 3.3.17, 3.4.0 to 3.4.13, 4.0.0 to 4.0.13, and 4.1.0 to 4.1.2.");
  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.7.49, 2.8.44, 3.3.18, 3.4.14, 4.0.14, and 4.1.3.

  NOTE: No fixes are provided for Symfony 3.0, 3.1, and 3.2 as they are not maintained anymore.
  It is recommended to upgrade to a supported version.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-14774-possible-host-header-injection-when-using-httpcache");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.7.0", test_version2: "2.7.48" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.49", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.43" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.44", install_path: location);
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.3.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.18", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.14", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.14", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.1.0", test_version2: "4.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
