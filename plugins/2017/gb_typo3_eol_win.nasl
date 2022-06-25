###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_eol_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# TYPO3 End of Life Detection (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113032");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 14:46:47 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 End of Life Detection (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TYPO3/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"The TYPO3 version on the remote host has reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of TYPO3 is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the TYPO3 version on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://typo3.org/typo3-cms/roadmap/");

  exit(0);
}

CPE = "cpe:/a:typo3:typo3";

include( "misc_func.inc" );
include( "products_eol.inc" );
include( "version_func.inc" );
include( "host_details.inc" );
include( "http_func.inc" ); # For report_vuln_url()

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version  = infos['version'];
location = infos['location'];

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "TYPO3",
                              cpe: CPE,
                              version: version,
                              location: report_vuln_url( port: port, url: location, url_only: TRUE ),
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
