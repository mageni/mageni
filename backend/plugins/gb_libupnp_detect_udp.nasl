###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libupnp_detect_udp.nasl 4444 2016-11-08 11:27:13Z cfi $
#
# libupnp Detection (UDP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108015");
  script_version("$Revision: 4444 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-08 12:27:13 +0100 (Tue, 08 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-11-08 11:37:33 +0100 (Tue, 08 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libupnp Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/pupnp/");

  script_tag(name:"summary", value:"Detection of libupnp

  The script sends a connection request to the server and attempts to detect the presence of libupnp and to
  extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

port = get_kb_item( "Services/udp/upnp" );
if( ! port ) port = 1900;
server = get_kb_item( "upnp/" + port + "/server" );

if( server && "sdk for upnp" >< tolower( server ) ) {

  version = "unknown";

  vers = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:server, icase:TRUE );
  if( ! isnull( vers[2] ) ) version = vers[2];

  set_kb_item( name:"libupnp/" + port + "/version", value:version );
  set_kb_item( name:"libupnp/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:libupnp_project:libupnp:" );
  if( ! cpe )
    cpe = 'cpe:/a:libupnp_project:libupnp';

  register_product( cpe:cpe, location:"/", port:port, proto:"udp" );

  log_message( data:build_detection_report( app:"libupnp",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            proto:"udp",
                                            port:port );
}

exit( 0 );
