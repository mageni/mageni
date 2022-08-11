###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service_3digits.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Service Detection (3 ASCII digit codes like FTP, SMTP, NNTP...)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.14773");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection (3 ASCII digit codes like FTP, SMTP, NNTP...)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl"); # cifs445.nasl
  script_require_ports("Services/three_digits");
  # "rpcinfo.nasl", "dcetest.nasl"

  script_xref(name:"URL", value:"https://www.mageni.net");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It attempts to
  identify services that return 3 ASCII digit codes (ie: FTP, SMTP, NNTP, ...)");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("global_settings.inc");

function read_answer( socket ) {

  local_var r, answer, i, retry;

  retry = 2;

  repeat {
    for( i = 0; i <= retry; i ++ ) {
      r = recv_line( socket:socket, length:4096 );
      if( strlen( r ) > 0 ) break;
    }
    answer += r;
  }
  until( ! r || r =~ '^[0-9]{3}[^-]' || strlen( answer ) > 1000000 );
  return answer;
}

port = get_kb_item( "Services/three_digits" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
banner = read_answer( socket:soc );

if( banner )
  replace_kb_item( name:"FindService/tcp/" + port + "/spontaneous", value:banner );
else
  debug_print( 'Banner is void on port ', port, ' \n' );

# 500 = Unknown command
# 502 = Command not implemented

# If HELP works, it is simpler than anything else
send( socket:soc, data:'HELP\r\n' );
help = read_answer( socket:soc );
if( help ) {
  replace_kb_item( name:"FindService/tcp/" + port + "/help", value:help );
  if( ! banner ) banner = help; # Not normal, but better than nothing
}

if( help !~ '^50[0-9]' ) {

  if( "ARTICLE" >< help || "NEWGROUPS" >< help || "XHDR" >< help || "XOVER" >< help || banner =~ "^[0-9]{3} .*(NNTP|NNRP)" ) {
    report_service( port:port, svc:"nntp", banner:banner );
    close( soc );
    exit( 0 );
  }

  # nb: this must come before FTP recognition.
  if( egrep(string:banner, pattern:"^220.*HylaFAX .*Version.*") || egrep( string:help, pattern:"^220.*HylaFAX .*Version.*" ) ) {
    report_service( port:port, svc:"hylafax", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( egrep( string:banner, pattern:"^220 HP GGW server \(version ([0-9.]+)\) ready" ) ) {
    register_service( port:port, proto:"hp-gsg", message: "A HP GGW server is running at this port." );
    log_message( port:port, data:"A HP GGW server is running at this port." );
    close( soc );
    exit( 0 );
  }

  if( eregmatch( string:help, pattern:".*[a-z]{32}.*Authentication required\." ) ) {
    register_service( port:port, proto:'varnish-cli', message:"A Varnish control terminal seems to be running on this port." );
    log_message( port:port, data:"A Varnish control terminal seems to be running on this port." );
    close( soc );
    exit( 0 );
  }

  # nb: this must come before FTP recognition.
  if( egrep( pattern:"^101", string:banner ) && ( egrep( pattern:"[a-zA-Z]+broker", string:banner, icase:TRUE ) ||
      egrep( pattern:"portmapper tcp PORTMAPPER", string:banner ) ) ) {
    # iMQ Broker Rendezvous(imqbrokerd)
    register_service( port:port, proto:"imqbrokerd" );
    log_message( port:port, data:"A Message Queue broker is running at this port." );
    close( soc );
    exit( 0 );
  }

  if( "PORT" >< help || "PASV" >< help ) {
    report_service( port:port, svc:"ftp", banner:banner );
    close( soc );
    exit( 0 );
  }

  # Code from find_service2.nasl
  if( help =~ '^220 .* SNPP ' || egrep( string:help, pattern:'^214 .*PAGE' ) ) {
    report_service( port:port, svc:"snpp", banner:banner );
    close( soc );
    exit( 0 );
  }

  if( egrep( string:help, pattern:'^214-? ') && 'MDMFMT' >< help ) {
    report_service( port:port, svc:"hylafax-ftp", banner:banner );
    close( soc );
    exit( 0 );
  }
}

send( socket:soc, data:'HELO mail.example.org\r\n' );
helo = read_answer( socket:soc );

if( egrep( string:helo, pattern:'^250' ) ) {
  report_service( port:port, svc:"smtp", banner:banner );
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'DATE\r\n' );
date = read_answer( socket:soc );

if( date =~ '^111[ \t]+2[0-9]{3}[01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]' ) {
  report_service( port:port, svc:"nntp", banner:banner );
  close( soc );
  exit( 0 );
}

ftp_commands = make_list( "CWD", "SYST", "PORT", "PASV" );
ko = 0;

foreach cmd( ftp_commands ) {

  send( socket:soc, data:cmd + '\r\n' );
  r = read_answer( socket: soc );

  if( egrep( string:r, pattern:'^50[0-9]' ) )
    ko++;
  debug_print( 'Answer to ', cmd, ': ', r );

  if( cmd == "SYST" ) {
    # We store the result of SYST just in case. Most (>99%) FTP servers answer
    # "Unix Type: L8" so this is not very informative
    v = eregmatch( string:r, pattern:'^2[0-9][0-9] +(.*)[ \t\r\n]*$' );
    if( ! isnull( v ) )
      set_kb_item( name:"ftp/" + port + "/syst", value:v[1] );
  }
}

close( soc );

if( ! ko ) {
  report_service( port:port, svc:"ftp", banner:banner );
  exit( 0 );
}

# Code from find_service2.nasl:
# SNPP, HylaFAX FTP, HylaFAX SPP, agobot.fo, IRC bots, WinSock server,
# Note: this code must remain in find_service2.nasl until we think that
# all find_service.nasl are up to date
if( egrep( pattern:"^220 Bot Server", string:help ) ||
    raw_string( 0xb0, 0x3e, 0xc3, 0x77, 0x4d, 0x5a, 0x90 ) >< help ) {
  report_service( port:port, svc:"agobot.fo", banner:banner );
  exit( 0 );
}

if( "500 P-Error" >< help && "220 Hello" >< help ) { # or banner?
  report_service( port:port, svc:"unknown_irc_bot", banner:banner );
  exit( 0 );
}

if( "220 WinSock" >< help ) { # or banner?
  report_service( port:port, svc:"winsock", banner:banner );
  exit( 0 );
}

if( egrep( pattern:"^200 .* (PWD Server|poppassd)", string:banner ) ) {
  register_service( port:port, proto:"pop3pw" );
  exit( 0 );
}

if( substr( banner, 0, 3 ) == '200 ' ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    vt_strings = get_vt_strings();
    banner = read_answer( socket:soc );
    send( socket:soc, data:string( "USER ", vt_strings["lowercase"], "\r\n" ) );
    r = read_answer( socket: soc );
    if( strlen( r ) > 3 && substr( r, 0, 3 ) == '200 ' ) {
      send( socket:soc, data:string( "PASS ", vt_strings["lowercase_rand"], "\r\n" ) );
      r = read_answer( socket:soc );
      if( strlen( r ) > 3 && substr( r, 0, 3) == '500 ' ) {
        register_service( port:port, proto:'pop3pw' );
        close( soc );
        exit( 0 );
      }
    }
    close( soc );
  }
}

# Give it to find_service2 & others
register_service( port:port, proto:'unknown' );
set_unknown_banner( port:port, banner:banner );

report  = 'Although this service answers with 3 digit ASCII codes like FTP, SMTP or NNTP servers, the Scanner was unable to identify it.\n\n';
report += 'This is highly suspicious and might be a backdoor; in this case, your system is compromised and an attacker can control it remotely.\n\n';
report += '** If you know what it is, consider this message as a false alert and please report it.\n\n';
report += 'Solution : disinfect or reinstall your operating system.';

log_message( port:port, data:report );
exit( 0 );