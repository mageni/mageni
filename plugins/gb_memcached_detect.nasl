###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_detect.nasl 8989 2018-03-01 07:41:40Z cfischer $
#
# Memcached Version Detection (TCP)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

# Note: Another product MemcacheDB (http://memcachedb.org/) is compatible with
# the memcache protocol used here (see also gb_memcachedb_detect.nasl).
# As MemcacheDB had its last release in 2008 we're currently don't care about this.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800714");
  script_version("$Revision: 8989 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-01 08:41:40 +0100 (Thu, 01 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Memcached Version Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service1.nasl", "gb_memcached_detect_udp.nasl");
  script_require_ports("Services/memcached", 11211);

  script_xref(name:"URL", value:"https://www.memcached.org/");

  script_tag(name:"summary", value:"Detection of Memcached.

  The script sends a TCP connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/memcached" );
if( ! port ) port = 11211;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = string("version\r\n");
send( socket:soc, data:data );
res = recv( socket:soc, length:64 );

close( soc );
if( ! res ) exit( 0 );
if( res !~ '^VERSION [0-9.\r\n]+$' ) exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res );
if( isnull( version[1] ) ) exit( 0 );

install = port + "/tcp";
set_kb_item( name:"Memcached/detected", value:TRUE );
set_kb_item( name:"Memcached/version", value:version[1] );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcached:memcached:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:memcached:memcached";

register_product( cpe:cpe, location:install, port:port );
register_service( port:port, proto:"memcached" );

log_message( data:build_detection_report( app:"Memcached",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );
exit( 0 );
