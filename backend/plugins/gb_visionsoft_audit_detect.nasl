# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108892");
  script_version("2020-08-27T12:38:16+0000");
  script_tag(name:"last_modification", value:"2020-08-28 09:48:35 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-27 11:22:12 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Visionsoft Audit Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/visionsoft-audit", 5957);

  script_tag(name:"summary", value:"Detection of Visionsoft Audit based on the
  Visionsoft Audit on Demand Service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("cpe.inc");

port = get_port_for_service( default:5957, proto:"visionsoft-audit" );

sock = open_sock_tcp( port );
if( ! sock )
  exit( 0 );

banner = recv_line( socket:sock, length:1024 );
if( ! banner || "Visionsoft Audit on Demand Service" >!< banner ) {
  close( sock );
  exit( 0 );
}

set_kb_item( name:"visionsoft/audit/detected", value:TRUE );
install = port + "/tcp";
version = "unknown";
concl = chomp( banner );

vers_banner = recv_line( socket:sock, length:1024 );
close( sock );

# Version: 1907
# Version: 303121750
# Version: 12.4.0.0
vers = eregmatch( string:vers_banner, pattern:"Version: ([0-9.]+)", icase:FALSE );
if( vers[1] ) {
  version = vers[1];
  concl += '\n' + vers[0];
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:visionsoft:audit:" );
if( ! cpe )
  cpe = "cpe:/a:visionsoft:audit";

register_service( port:port, proto:"visionsoft-audit" );
register_product( cpe:cpe, location:install, port:port, service:"visionsoft-audit" );

log_message( data:build_detection_report( app:"Visionsoft Audit", version:version, install:install, cpe:cpe, concluded:concl ),
             port:port );

exit( 0 );
