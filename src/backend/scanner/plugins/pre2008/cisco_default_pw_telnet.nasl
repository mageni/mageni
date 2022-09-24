###############################################################################
# OpenVAS Vulnerability Test
#
# Authors:
# Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# Copyright:
# Copyright (C) 2007 Javier Fernandez-Sanguino and Renaud Deraison
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

# nb: Previously this was a single "cisco_default_pw.nasl" script which got split into
# "cisco_default_pw_ssh.nasl" and "cisco_default_pw_telnet.nasl" to have dedicated VTs for each
# protocol. The creation_date of both VTs have been kept on purpose.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.23938");
  script_version("2022-09-22T11:13:35+0000");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2022-09-22 11:13:35 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Device Default Password (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2007 Javier Fernandez-Sanguino and Renaud Deraison");
  script_family("CISCO");
  script_dependencies("telnetserver_detect_type_nd_version.nasl","gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"The remote Cisco device has a default password set for the
  Telnet login.");

  script_tag(name:"impact", value:"This allows an attacker to get a lot information about the
  network, and possibly to shut it down if the 'enable' password is not set either or is also a
  default password.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("default_account.inc");
include("default_credentials.inc");
include("dump.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

# Functions modified from the code available from default_account.inc (which is biased to UNIX)
function check_cisco_account_telnet( port, login, password ) {

  local_var port, login, password;
  local_var banner, soc, msg, r, cmd, report;

  if( ! banner = telnet_get_banner( port:port ) )
    return 0;

  # nb: Check for banner, covers the case of Cisco telnet as well as the case of a console server to a Cisco port
  # Note: banners of cisco systems are not necessarily set, so this might lead to false negatives!
  if( stridx( banner, "User Access Verification" ) == -1 && stridx( banner, "assword:" ) == -1 )
    return 0;

  if( ! soc = open_sock_tcp( port ) )
    return 0;

  msg = telnet_negotiate( socket:soc, pattern:"(ogin:|asscode:|assword:)" );

  if( strlen( msg ) ) {
    # The Cisco device might be using an AAA access model or have configured users:
    if( stridx( msg, "sername:" ) != -1 || stridx( msg, "ogin:" ) != -1 ) {
      send( socket:soc, data:string( login, "\r\n" ) );
      msg = recv_until( socket:soc, pattern:"(assword:|asscode:)" );
    }

    # Device can answer back with {P,p}assword or {P,p}asscode if we don't get it then fail and close
    if( ! msg || ( stridx( msg, "assword:" ) == -1 && stridx( msg, "asscode:" ) == -1 ) ) {
      close( soc );
      return 0;
    }

    if( isnull( password ) )
      password = "";

    send( socket:soc, data:string( password, "\r\n" ) );
    r = recv( socket:soc, length: 4096 );

    # TODO: could check for Cisco's prompt here, it is typically the device name followed by '>'
    # But the actual regexp is quite complex, from Net-Telnet-Cisco:
    #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

    # Send a 'show ver', most users (regardless of privilege level) should be able to do this
    cmd = "show ver";
    send( socket:soc, data:string( cmd, "\r\n" ) );
    # TODO: This is probably not generic enough. Some Cisco devices don't use IOS but CatOS for example
    r = recv_until( socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS) Software|assword:|asscode:|ogin:|% Bad password)" );

    # TODO: It might want to change the report so it tells which user / passwords have been found
    if( "Cisco Internetwork Operating System Software" >< r || "Cisco IOS Software" >< r || r =~ "IOS(-| )X(E|R)" ) {
      report = 'It was possible to log in as \'' + login + '\'/\'' + password + '\'\n\n';
      report += 'Response to the "' + cmd + '" command (truncated):\n\n"' + substr( r, 0, 250 );
      security_message( port:port, data:report );
      close( soc );
      exit( 0 );
    }

    # TODO: it could also try 'enable' here and see if it's capable of accessing
    # the privilege mode with the same password, or do it in a separate module
  }

  close( soc );
  return 0;
}

port = telnet_get_port( default:23 );

check_cisco_account_telnet( port:port, login:"cisco", password:"cisco" );
check_cisco_account_telnet( port:port, login:"", password:"" );

p = script_get_preference( "Use complete password list (not only vendor specific passwords)", id:1 );
if( "yes" >< p )
  clist = try();
else
  clist = try( vendor:"cisco" ); # get all cisco relevant credentials

if( ! clist )
  exit( 0 );

# nb: Currently unclear why this has been used like this...
if( ! safe_checks() ) {
  foreach credential( clist ) {

    # Handling of user uploaded credentials which requires to escape a ';' or ':'
    # in the user/password so it doesn't interfere with our splitting below.
    credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
    credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

    user_pass = split( credential, sep:":", keep:FALSE );
    if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) {
      # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
      # GSA is stripping ';' from the NVT description. Keeping both in here
      # for backwards compatibility with older scan configs.
      user_pass = split( credential, sep:";", keep:FALSE );
      if( isnull( user_pass[0] ) || isnull( user_pass[1] ) )
        continue;
    }

    user = chomp( user_pass[0] );
    pass = chomp( user_pass[1] );

    user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
    pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
    user = str_replace( string:user, find:"#sem_new#", replace:":" );
    pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

    if( tolower( pass ) == "none" )
      pass = "";

    check_cisco_account_telnet( port:port, login:user, password:pass );
  }
}

exit( 0 );
