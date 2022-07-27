###############################################################################
# OpenVAS Vulnerability Test
#
# Compaq Web-based Management Login
#
# Authors:
# Christoff Breytenbach <christoff@sensepost.com>
#
# Copyright:
# Copyright (C) 2004 SensePost
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

# - Checks only for passwords on Compaq Web-based / HP System Management
#   Agent on HTTPS (2381/tcp), and not on older versions with login
#   still on HTTP (2301/tcp)
# - Tested on CompaqHTTPServer 4.1, 4.2, 5.0, 5.7

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11879");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Compaq Web-based Management Login");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 SensePost");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2381);
  script_mandatory_keys("CompaqHTTPServer/banner");

  script_tag(name:"summary", value:"Checks the administrator account on Compaq Web-based Management / HP System Management
  agents for the default or predictable passwords.");

  script_tag(name:"solution", value:"Ensure that all passwords for Compaq Web-based Management / HP System Management Agent
  accounts are set to stronger, less easily guessable, alternatives. As a further precaution, use the 'IP Restricted Logins'
  setting to allow only authorised IP's to manage this agent.");

  script_tag(name:"insight", value:"The Compaq Web-based Management / HP System Management Agent active on the remote host
  is configured with the default, or a predictable, administrator password.

  Depending on the agents integrated, this allows an attacker to view sensitive and verbose system information, and may even
  allow more active attacks such as rebooting the remote system. Furthermore, if an SNMP agent is configured on the remote
  host it may disclose the SNMP community strings in use, allowing an attacker to set device configuration if the 'write'
  community string is uncovered.

  To manually test for this bug, you can log into the Compaq web server via a browser (https://example.com:2381/).
  Log in with a username/password combination of administrator/");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

passlist = make_list( 'administrator', 'admin', 'cim', 'cim7', 'password' );

port = get_http_port( default:8086 );

req = http_get( item:"/cpqlogin.htm?RedirectUrl=/&RedirectQueryString=", port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res )
  exit( 0 );

if( ( res =~ "^HTTP/1\.[01] 200" ) && ( "Server: CompaqHTTPServer/" >< res ) && ( "Set-Cookie: Compaq" >< res ) ) {

  foreach pass( passlist ) {

    cookie = eregmatch( pattern:"Set-Cookie: (.*);", string:res );
    if( isnull( cookie[1] ) )
      exit( 0 );

    poststr = string( "redirecturl=&redirectquerystring=&user=administrator&password=", pass );
    req = string( "POST /proxy/ssllogin HTTP/1.0\r\n",
                  "Cookie: " + cookie[1], "\r\n",
                  "Content-Length: ", strlen( poststr ),
                  "\r\n\r\n",
                  poststr, "\r\n" );
    res = http_keepalive_send_recv( port:port, data:req );
    if( "CpqElm-Login: success" >< res ) {
      report = "It was possible to login with the password'" + pass + "'.";
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );