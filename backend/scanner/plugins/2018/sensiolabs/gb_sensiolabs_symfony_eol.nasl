###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sensiolabs_symfony_eol.nasl 10853 2018-08-09 08:45:51Z jschulte $
#
# Sensiolabs Symfony End of Life Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112349");
  script_version("$Revision: 10853 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 10:45:51 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-06 13:03:00 +0200 (Mon, 06 Aug 2018)");
  script_name("Sensiolabs Symfony End of Life Detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_xref(name:"URL", value:"https://symfony.com/roadmap");

  script_tag(name:"summary", value:"Sensiolabs Symfony on the remote host has reached the End-of-Life and should
  not be used anymore.");

  script_tag(name:"impact", value:"An End-of-Life version of Sensiolabs Symfony is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update Symfony to the latest available and supported version.");

  script_tag(name:"vuldetect", value:"Checks if an unsupported version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "products_eol.inc" );
include( "misc_func.inc" );
include( "http_func.inc" ); # For report_vuln_url()

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {

  report = build_eol_message( name: "Sensiolabs Symfony",
                              cpe: CPE,
                              version: version,
                              location: report_vuln_url( port: port, url: location, url_only: TRUE ),
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
