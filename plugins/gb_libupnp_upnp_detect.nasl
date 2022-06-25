###############################################################################
# OpenVAS Vulnerability Test
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
  script_version("2020-06-08T12:04:49+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:04:49 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2016-11-08 11:37:33 +0100 (Tue, 08 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libupnp Detection (UPnP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

include("host_details.inc");
include("misc_func.inc");

port = get_port_for_service( default:1900, proto:"upnp", ipproto:"udp" );

server = get_kb_item( "upnp/" + port + "/server" );

if( server && "sdk for upnp" >< tolower( server ) ) {

  version = "unknown";

  vers = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:server, icase:TRUE );
  if( ! isnull( vers[2] ) ) version = vers[2];

  set_kb_item( name:"libupnp/detected", value:TRUE );
  set_kb_item( name:"libupnp/upnp/detected", value:TRUE );
  set_kb_item( name:"libupnp/upnp/port", value: port );
  set_kb_item( name:"libupnp/upnp/" + port + "/version", value:version );
  set_kb_item( name:"libupnp/upnp/" + port + "/concluded", value:vers[0] );
}

exit( 0 );
