###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_akka_http_dos_vuln_aug18.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Akka HTTP 10.0.x, 10.1.x Denial of Service vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.113262");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-31 13:43:24 +0200 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16131");

  script_name("Akka HTTP 10.0.x, 10.1.x Denial of Service vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_akka_http_detect.nasl");
  script_mandatory_keys("akka_http/installed");

  script_tag(name:"summary", value:"Akka HTTP is prone to a Denial of Service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An attacker can use a Zip Bomb attack using the decodeRequest and
  decodeRequestWith directives to cause excessive memory usage
  and eventually a total crash of the application.");
  script_tag(name:"affected", value:"Akka HTTP versions 10.0.0 through 10.1.12 and 10.1.0 through 10.1.3.");
  script_tag(name:"solution", value:"Update to version 10.1.13 or 10.1.4 respectively.");

  script_xref(name:"URL", value:"https://akka.io/blog/news/2018/08/30/akka-http-dos-vulnerability-found");
  script_xref(name:"URL", value:"https://github.com/akka/akka-http/issues/2137");

  exit(0);
}

CPE = "cpe:/a:akka:http";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "10.0.0", test_version2: "10.0.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.13" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "10.1.0", test_version2: "10.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.1.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
