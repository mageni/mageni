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
  script_oid("1.3.6.1.4.1.25623.1.0.104329");
  script_version("2022-09-22T11:13:35+0000");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2022-09-22 11:13:35 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Device Default Password (SSH)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2007 Javier Fernandez-Sanguino and Renaud Deraison");
  script_family("CISCO");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"The remote Cisco device has a default password set for the SSH
  login.");

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
include("port_service_func.inc");
include("ssh_func.inc");

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

# Functions modified from the code available from default_account.inc (which is biased to UNIX)
function check_cisco_account_ssh( port, login, password ) {

  local_var port, login, password;
  local_var soc, ret, cmd, r, report;

  if( ! soc = open_sock_tcp( port ) )
    return 0;

  ret = ssh_login( socket:soc, login:login, password:password );
  if( ret == 0 ) {
    cmd = "show ver";
    r = ssh_cmd( socket:soc, cmd:"show ver", timeout:60, nosh:TRUE );
    close( soc );

    if( "Cisco Internetwork Operating System Software" >< r || "Cisco IOS Software" >< r || r =~ "IOS(-| )X(E|R)" ) {
      report = 'It was possible to log in as \'' + login + '\'/\'' + password + '\'\n\n';
      report += 'Response to the "' + cmd + '" command (truncated):\n\n"' + substr( r, 0, 250 );
      security_message( port:port, data:report );
      exit( 0 );
    }
  } else {
    close( soc );
    return 0;
  }
}

port = ssh_get_port( default:22 );

check_cisco_account_ssh( port:port, login:"cisco", password:"cisco" );
check_cisco_account_ssh( port:port, login:"", password:"" );

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

    check_cisco_account_ssh( port:port, login:user, password:pass );
  }
}

exit( 0 );
