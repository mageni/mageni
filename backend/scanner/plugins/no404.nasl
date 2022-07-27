###############################################################################
# OpenVAS Vulnerability Test
# $Id: no404.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# No 404 check
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
# - rewritten in parts by H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2000 RD / H D Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10386");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("No 404 check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 RD / H D Moore");
  script_family("Web Servers");
  script_dependencies("http_login.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"This web server is [mis]configured in that it does not return
  '404 Not Found' error codes when a non-existent file is requested, perhaps returning a site map,
  search page or authentication page instead.

  The Scanner enabled some counter measures for that, however they might be insufficient. If a great
  number of security holes are produced for this port, they might not all be accurate");

  script_tag(name:"summary", value:"Remote web server does not reply with 404 error code.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# TODO: At some code points a log_message() is done with a reference to the no404 assumption
# above but the server is just marked as "broken" because of an detected embedded web server.

include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("404.inc"); # For errmessages_404 list

counter = 0;

function check( url, port ) {

  local_var req, res;

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( data:req, port:port );

  if( isnull( res ) ) counter++;
  #TBD: Also set webserver as broken on exit?
  if( counter > 2 ) exit(0);

  return( res );
}

function find_err_msg( buffer ) {

  local_var errmsg;

  foreach errmsg( errmessages_404 ) {
    if( egrep( pattern:errmsg, string:buffer, icase:TRUE ) ) {
      if( debug_level ) display( 'no404 - "' + errmsg + '" found in "' + buffer + '\n' );
      return( errmsg );
    }
  }
  return( 0 );
}

# nb: This build list of test urls, avoids that basename contains the word "404"
basename = "404";
while( "404" >< basename ) basename = "/" + rand_str( length:12 );

badurls = make_list(
basename + ".html",
basename + ".htm",
basename + ".cgi",
basename + ".sh",
basename + ".pl",
basename + ".inc",
basename + ".shtml",
basename + ".asp",
basename + ".php",
basename + ".php3",
basename + ".php4",
basename + ".php5",
basename + ".php7",
basename + ".cfm",

"/cgi-bin" + basename + ".html",
"/cgi-bin" + basename + ".htm",
"/cgi-bin" + basename + ".cgi",
"/cgi-bin" + basename + ".sh",
"/cgi-bin" + basename + ".pl",
"/cgi-bin" + basename + ".inc",
"/cgi-bin" + basename + ".shtml",
"/cgi-bin" + basename + ".php",
"/cgi-bin" + basename + ".php3",
"/cgi-bin" + basename + ".php4",
"/cgi-bin" + basename + ".php5",
"/cgi-bin" + basename + ".php7",
"/cgi-bin" + basename + ".cfm",

"/scripts" + basename + ".html",
"/scripts" + basename + ".htm",
"/scripts" + basename + ".cgi",
"/scripts" + basename + ".sh",
"/scripts" + basename + ".pl",
"/scripts" + basename + ".inc",
"/scripts" + basename + ".shtml",
"/scripts" + basename + ".php",
"/scripts" + basename + ".php3",
"/scripts" + basename + ".php4",
"/scripts" + basename + ".php5",
"/scripts" + basename + ".php7",
"/scripts" + basename + ".cfm" );

function my_exit( then, port, host ) {

  local_var now, then, port, host;

  now = unixtime();
  if( now - then > 60 ) {
    report = "The remote web server is very slow - it took " + int(now - then) + " seconds to " +
             "execute the plugin no404.nasl (it usually only takes a few seconds)." + '\n\n' +
             "In order to keep the scan total time to a reasonable amount, the remote web server " +
             "has not been tested." + '\n\n' +
             "If you want to test the remote server fix it to have it reply to the scanners requests " +
             "in a reasonable amount of time.";

    log_message( port:port, data:report );
    http_set_is_marked_broken( port:port, host:host );
  }
  exit( 0 );
}

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

then = unixtime();

foreach badurl( badurls ) {

  if( debug_level ) display( 'no404 - Checking URL ' + badurl + ' on port ' + port + '\n' );
  ret = check( url:badurl, port:port );

  if( ! ( ret == 0 ) ) {

    # WebMin's miniserv and CompaqDiag behave strangely
    if( egrep( pattern:"^Server: MiniServ/", string:ret ) ) {
      http_set_no404_string( port:port, host:host, string:"HTTP" );
      log_message( port:port );
      exit( 0 );
    }

    # MailEnable-HTTP does not handle connections fast enough
    if( egrep( pattern:"^Server: MailEnable-HTTP/", string:ret ) ) {
      http_set_no404_string( port:port, host:host, string:"HTTP" );
      http_set_is_marked_broken( port:port, host:host );
      log_message( port:port );
      exit( 0 );
    }

    if( egrep( pattern:"^Server: CompaqHTTPServer/", string:ret ) ) {
      http_set_no404_string( port:port, host:host, string:"HTTP" );
      http_set_is_marked_broken( port:port, host:host );
      log_message( port:port );
      exit( 0 );
    }

    # This is not a web server
    if( egrep( pattern:"^DAAP-Server:", string:ret ) ) {
      http_set_is_marked_broken( port:port, host:host );
      log_message( port:port );
      exit( 0 );
    }

    raw_http_line = egrep( pattern:"^HTTP/", string:ret );

    if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:raw_http_line ) ) {

      # nb: look for common "not found" indications
      not_found = find_err_msg( buffer:ret );
      if( not_found != 0 ) {
        if( debug_level ) display( 'no404 - 200: Using string: ' + not_found + '\n' );
        http_set_no404_string( port:port, host:host, string:string( not_found ) );
        log_message( port:port );
        my_exit( then:then, port:port, host:host );
      } else {

        title = egrep( pattern:"<title", string:ret, icase:TRUE );
        if( title ) {
          title = ereg_replace(string:title, pattern:".*<title>(.*)</title>.*", replace:"\1", icase:TRUE);
          if( title ) {
            if( debug_level ) display( 'no404 - using string from title tag: ' + title + '\n' );
            http_set_no404_string( port:port, host:host, string:title );
            log_message( port:port );
            my_exit( then:then, port:port, host:host );
          }
        }

        body = egrep( pattern:"<body", string:ret, icase:TRUE );
        if( body ) {
          body = ereg_replace( string:body, pattern:"<body(.*)>", replace:"\1", icase:TRUE );
          if( body ) {
            if( debug_level ) display( 'no404 - using string from body tag: ' + body + '\n' );
            http_set_no404_string( port:port, host:host, string:body );
            log_message( port:port );
            my_exit( then:then, port:port, host:host );
          }
        }

        # nb: get mad and give up
        if( debug_level ) display( 'no404 - argh! could not find something to match against.\n' );
        if( debug_level ) display( 'no404 - [response] ' + ret + '\n' );
        http_set_no404_string( port:port, host:host, string:"HTTP" );
        log_message( port:port, data:"Unfortunately, we were unable to find a way to recognize this page, so some CGI-related checks have been disabled." );
        my_exit( then:then, port:port, host:host );
      }
    }

    if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 30[12] ", string:raw_http_line ) ) {
      log_message( port:port, data:"CGI scanning will be disabled for this host." );
      http_set_no404_string( port:port, host:host, string:"HTTP" );
      my_exit( then:then, port:port, host:host ); # TODO: This is currently exiting on the first request on the root dir if that is always redirecting to e.g. /folder/
    }
  } else {
    if( debug_level ) display( 'no404 - An error occurred when trying to request: ' + badurl + '\n' );
  }
}

my_exit( then:then, port:port, host:host );
