###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcachedb_detect.nasl 8977 2018-02-28 10:59:57Z cfischer $
#
# MemcacheDB Version Detection
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

# Note: This product is supporting the same memcache protocol used by the
# gb_memcached_detect* NVTs. However MemcacheDB had its last release in
# 2008 so we're only checking the default 21201 port here and won't register
# the service via register_service().

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800716");
  script_version("$Revision: 8977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-28 11:59:57 +0100 (Wed, 28 Feb 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MemcacheDB Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Product detection");
  script_require_ports(21201); # See comment above

  script_xref(name:"URL", value:"http://memcachedb.org/");

  script_tag(name:"summary", value:"The script detects the installed version of MemcacheDB and sets
  the result into KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

# Default port used by MemcacheDB Daemon
port = 21201;
if( ! get_port_state( port ) ) exit( 0 );

data = string( "version \r\n" );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:data );
res = recv( socket:soc, length:1024 );
close( soc );
if( isnull( res ) ) exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res );
if( isnull( version[1] ) ) exit( 0 );

install = port + "/tcp";
set_kb_item( name:"MemcacheDB/installed", value:TRUE );
set_kb_item( name:"MemcacheDB/version", value:version[1] );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcachedb:memcached:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:memcachedb:memcached";

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"MemcacheDB",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );
exit( 0 );