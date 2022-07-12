###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_detect_udp.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Memcached Version Detection (UDP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

# Note: Another product MemcacheDB (http://memcachedb.org/) is compatible with
# the memcache protocol used here (see also gb_memcachedb_detect.nasl).
# As MemcacheDB had its last release in 2008 we're currently don't care about this.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108356");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-28 09:06:33 +0100 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Memcached Version Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 11211);

  script_xref(name:"URL", value:"https://www.memcached.org/");

  script_tag(name:"summary", value:"Detection of Memcached.

  The script sends a UDP connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"insight", value:"A public available Memcached service with enabled UDP support
  might be misused for Distributed Denial of Service (DDoS) attacks, dubbed 'Memcrashed'. This
  vulnerability is separately checked and reported in the NVT 'Memcached Amplification Attack
  (Memcrashed)' OID: 1.3.6.1.4.1.25623.1.0.108357.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

port = get_unknown_port( default:11211, ipproto:"udp" );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

# https://github.com/memcached/memcached/blob/master/doc/protocol.txt#L1166
req = raw_string( 0x00, 0x01,   # RequestID
                  0x00, 0x00,   # Sequence number
                  0x00, 0x01,   # Total number of datagrams in this message
                  0x00, 0x00 ); # Reserved for future use; must be 0
data = req + string("version\r\n");
send( socket:soc, data:data );
res = recv( socket:soc, length:64 );
close( soc );
if( ! res || strlen( res ) < 8 ) exit( 0 );
res_str = bin2string( ddata:res, noprint_replacement:' ' );

# nb: The service normally will answer with the same "req" raw_string above following by the version
# 0x0000:  00 01 00 00 00 01 00 00 56 45 52 53 49 4F 4E 20    ........VERSION
# 0x0010:  31 2E 34 2E 33 33 0D 0A                            1.4.33..
# but the check here is done more generic as some servers have responded
# with malloc_fails messages like the one below:
# 0x0000:  00 01 00 01 00 02 00 00 53 54 41 54 20 6D 61 6C    ........STAT mal
# 0x0010:  6C 6F 63 5F 66 61 69 6C 73 20 30 0D 0A 53 54 41    loc_fails 0..STA
if( hexstr( substr( res, 0, 7 ) ) !~ "^([0-9]+)$" || res_str !~ "VERSION [0-9.]+" ) exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res_str );
if( isnull( version[1] ) ) exit( 0 );

install = port + "/udp";
set_kb_item( name:"Memcached/detected", value:TRUE );
set_kb_item( name:"Memcached/version", value:version[1] );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcached:memcached:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:memcached:memcached";

register_product( cpe:cpe, location:install, port:port, proto:"udp" );
register_service( port:port, proto:"memcached", ipproto:"udp" );

log_message( data:build_detection_report( app:"Memcached",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port,
                                          proto:"udp" );
exit( 0 );
