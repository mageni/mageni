###############################################################################
# OpenVAS Vulnerability Test
# $Id: dns_server_tcp.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# DNS Server Detection (TCP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108018");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNS Server Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 53);

  script_tag(name:"summary", value:"A DNS Server is running at this Host.
  A Name Server translates domain names into IP addresses. This makes it
  possible for a user to access a website by typing in the domain name instead of
  the website's actual IP address.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("dns_func.inc");

# query '1.0.0.127.in-addr.arpa/PTR/IN'

data = raw_string( 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x01, 0x31, 0x01, 0x30, 0x01, 0x30,
                   0x03, 0x31, 0x32, 0x37, 0x07, 0x69,
                   0x6E, 0x2D, 0x61, 0x64, 0x64, 0x72,
                   0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
                   0x00, 0x0C, 0x00, 0x01 );

data = raw_string( 0x00, 0x28 ) + data;

port = get_unknown_port( default:53 ); # nb: At least Dnsmasq allows to configure a DNS port other then 53
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:data );
buf = recv( socket:soc, length:4096 );
if( isnull ( buf ) ) {
  close( soc );
  exit( 0 );
}

if( strlen( buf ) > 5 ) {
  if( ord( buf[4] ) & 0x80 ) {
    set_kb_item( name:"DNS/tcp/" + port, value:TRUE );
    set_kb_item( name:"DNS/identified", value:TRUE );
    banner = dnsVersionReq( soc:soc, proto:"tcp", port:port );
    if( banner ) report = 'The remote DNS server banner is:\n\n' + banner;
    register_service( port:port, ipproto:"tcp", proto:"domain", message:report );
    log_message( port:port, data:report, protocol:"tcp" );
  }
}

if( soc ) close( soc );

exit( 0 );