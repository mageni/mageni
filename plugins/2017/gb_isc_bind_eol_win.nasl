###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_eol_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# BIND End of Life Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113026");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 12:39:40 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BIND End of Life Detection (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"The BIND version on the remote host has reached the end of life and should not be used anymore.");
  script_tag(name:"impact", value:"An end of life version of BIND is not receiving any security updates from the vendor. Unfixed security vulnerabilities
    might be leveraged by an attacker to compromise the security of this host.");
  script_tag(name:"solution", value:"Update the BIND version on the remote host to a still supported version.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.isc.org/downloads/software-support-policy/");
  script_xref(name:"URL", value:"https://www.isc.org/downloads/");

  exit(0);
}

CPE = "cpe:/a:isc:bind";

include( "misc_func.inc" );
include( "products_eol.inc" );
include( "version_func.inc" );
include( "host_details.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "BIND",
                              cpe: CPE,
                              version: version,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

