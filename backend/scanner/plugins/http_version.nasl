###############################################################################
# OpenVAS Vulnerability Test
# $Id: http_version.nasl 11585 2018-09-25 07:09:41Z cfischer $
#
# HTTP Server type and version
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 H. Scholz & Contributors
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
  script_oid("1.3.6.1.4.1.25623.1.0.10107");
  script_version("$Revision: 11585 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 09:09:41 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 H. Scholz & Contributors");
  script_family("Web Servers");
  script_dependencies("no404.nasl", "webmin.nasl", "webmirror.nasl",
                      "embedded_web_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_add_preference(name:"Show full HTTP headers in output", type:"checkbox", value:"no");

  script_tag(name:"solution", value:"- Configure your server to use an alternate name like
  'Wintendo httpD w/Dotmatrix display'

  - Be sure to remove common logos like apache_pb.gif.

  - With Apache, you can set the directive 'ServerTokens Prod' to limit
  the information emanating from the server in its response headers.");

  script_tag(name:"summary", value:"This detects the HTTP Server's type and version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# TODO: Move to secpod_apache_detect.nasl
function get_apache_version( port ) {

  local_var port, req, res, soc, r, v;

  req = http_get( item:"/nonexistent_please_dont_exist", port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  r = egrep( pattern:"<ADDRESS>.*</ADDRESS>", string:res, icase:TRUE );
  if( ! r ) return NULL;

  v = ereg_replace( string:r, pattern:"<ADDRESS>(Apache/[^ ]*).*", replace:"\1", icase:TRUE );
  if( r == v ) {
    return NULL;
  } else {
    return v;
  }
}

# TODO: Move to gb_lotus_domino_detect.nasl
function get_domino_version( port ) {

  local_var port, req, res, soc, r, v;

  req = http_get( item:"/nonexistentdb.nsf", port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  r = egrep( pattern:".*Lotus-Domino .?Release.*", string:res );
  v = NULL;
  if( ! isnull( r ) ) {
    v = ereg_replace( pattern:".*Lotus-Domino .?Release ([^ <]*).*", replace:"Lotus-Domino/\1", string:r );
  }
  if( isnull( r ) || v == r ) {
    if( get_port_state( 25 ) ) {
      soc = open_sock_tcp( 25 );
      if( soc ) {
        r = recv_line( socket:soc, length:4096 );
        close( soc );
        v = ereg_replace( pattern:".*Lotus Domino .?Release ([^)]*).*", replace:"Lotus-Domino/\1", string:r );
        if( v == r ) {
          return NULL;
        } else {
          return v;
        }
      }
    }
    return NULL;
  } else {
    return v;
  }
}

show_headers = script_get_preference( "Show full HTTP headers in output" );
report = 'The remote web server type is :\n\n';

port = get_http_port( default:80 );

# nb: Always keep http_get() before http_open_socket() as the first could
# fork with multiple vhosts and the child's would share the same socket
# causing race conditions and similar.
data = http_get( item:"/", port:port );

soc = http_open_socket( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:data );
res = http_recv_headers2( socket:soc );
http_close_socket( soc );
if( ! res || "Server: " >!< res ) exit( 0 );

svrline = egrep( pattern:"^(DAAP-)?Server:", string:res ) ;
svr = ereg_replace( pattern:".*Server: (.*)$", string:svrline, replace:"\1" );

if( "Apache" >< svr && "Apache-Coyote" >!< svr ) {
  if( "Apache/" >< svr ) {
    report += svr + '\n\nSolution : You can set the directive "ServerTokens Prod" to limit\nthe information emanating from the server in its response headers.';
  } else {
    svr2 = get_apache_version( port:port );
    if( ! isnull( svr2 ) ) {
      report += svr2 + '\n\nThe "ServerTokens" directive is set to ProductOnly\n' +
                       'however we could determine that the version of the remote\n' +
                       'server by requesting a non-existent page.\n';
      svrline = 'Server: ' + svr2 + '\r\n';
      replace_kb_item( name:"www/real_banner/" + port + "/", value:svrline );
      if( ! get_kb_item( "www/banner/" + port + "/" ) ) {
        replace_kb_item( name:"www/banner/" + port + "/", value:svrline );
      }
    } else {
      report += svr + '\nand the "ServerTokens" directive is ProductOnly\nApache does not permit to hide the server type.\n';
    }
  }
} else {
  if( "Lotus-Domino" >< svr ) {
    if( egrep( pattern:"Lotus-Domino/[1-9]\.[0-9]", string:svr ) ) {
      report += svr;
    } else {
      svr2 = get_domino_version(port:port);
    }
    if( ! isnull( svr2 ) ) {
      report += svr2 + '\n\nThe product version is hidden but we could determine it by\n' +
                       'requesting a non-existent .nsf file or connecting to port 25\n';
      svrline = 'Server: ' + svr2 + '\r\n';
      replace_kb_item( name:"www/real_banner/" + port + "/nonexistentdb.nsf", value:svrline );
      if( ! get_kb_item( "www/banner/" + port + "/nonexistentdb.nsf" ) ) {
        replace_kb_item( name:"www/banner/" + port + "/nonexistentdb.nsf", value:svrline );
      }
    } else {
      report += svr;
    }
  } else {
    report += svr;
  }
}

# put the name of the web server in the KB
if( egrep( pattern:"^Server:.*Domino.*", string:svrline ) )
  set_kb_item( name:"www/domino", value:TRUE );

if( egrep( pattern:"^Server:.*Apache.*", string:svrline ) )
  set_kb_item( name:"www/apache", value:TRUE );

if( egrep( pattern:"^Server:.*Apache.* Tomcat/", string:svrline, icase:TRUE ) )
  set_kb_item( name:"www/tomcat", value:TRUE );

if( egrep( pattern:"^Server:.*Microsoft.*", string:svrline ) )
  set_kb_item( name:"www/iis", value:TRUE );

if( egrep( pattern:"^Server:.*Zope.*", string:svrline ) )
  set_kb_item( name:"www/zope", value:TRUE );

if( egrep( pattern:"^Server:.*CERN.*", string:svrline ) )
  set_kb_item( name:"www/cern", value:TRUE );

if( egrep( pattern:"^Server:.*Zeus.*", string:svrline ) )
  set_kb_item( name:"www/zeus", value:TRUE );

if( egrep( pattern:"^Server:.*WebSitePro.*", string:svrline ) )
  set_kb_item( name:"www/websitepro", value:TRUE );

if( egrep( pattern:"^Server:.*NCSA.*", string:svrline ) )
  set_kb_item( name:"www/ncsa", value:TRUE );

if( egrep( pattern:"^Server:.*Netscape-Enterprise.*", string:svrline ) ) {
  set_kb_item( name:"www/iplanet", value:TRUE );
  set_kb_item( name:"www/netscape_servers", value:TRUE );
}

if( egrep( pattern:"^Server:.*Netscape-Administrator.*", string:svrline ) ) {
  set_kb_item( name:"www/iplanet", value:TRUE );
  set_kb_item( name:"www/netscape_servers", value:TRUE );
}

if( egrep( pattern:"^Server:.*thttpd/.*", string:svrline ) )
  set_kb_item( name:"www/thttpd", value:TRUE );

if( egrep( pattern:"^Server:.*WDaemon.*", string:svrline ) )
  set_kb_item( name:"www/wdaemon", value:TRUE );

if( egrep( pattern:"^Server:.*SAMBAR.*", string:svrline ) )
  set_kb_item( name:"www/sambar", value:TRUE );

if( egrep( pattern:"^Server:.*IBM-HTTP-Server.*", string:svrline ) )
  set_kb_item( name:"www/ibm-http", value:TRUE );

if( egrep( pattern:"^Server:.*Alchemy.*", string:svrline ) )
  set_kb_item( name:"www/alchemy", value:TRUE );

if( egrep( pattern:"^Server:.*Rapidsite/Apa.*", string:svrline ) )
  set_kb_item( name:"www/apache", value:TRUE );

if( egrep( pattern:"^Server:.*Statistics Server.*", string:svrline ) )
  set_kb_item( name:"www/statistics-server", value:TRUE );

if( egrep( pattern:"^Server:.*CommuniGatePro.*", string:svrline ) )
  set_kb_item( name:"www/communigatepro", value:TRUE );

if( egrep( pattern:"^Server:.*Savant.*", string:svrline ) )
  set_kb_item( name:"www/savant", value:TRUE );

if( egrep( pattern:"^Server:.*StWeb.*", string:svrline ) )
  set_kb_item( name:"www/stweb", value:TRUE );

if( egrep( pattern:"^Server:.*StWeb.*", string:svrline ) )
  set_kb_item( name:"www/apache", value:TRUE );

if( egrep( pattern:"^Server:.*Oracle HTTP Server.*", string:svrline ) ) {
  set_kb_item( name:"www/OracleApache", value:TRUE );
  # TODO: Move into own Detection-NVT and catch the version
  register_and_report_cpe( app:"Oracle Http Server", insloc:port + "/tcp", regPort:port, concluded:svrline, base:"cpe:/a:oracle:http_server:", expr:"^([0-9.]+([a-z0-9]+)?)" );
}

if( egrep( pattern:"^Server:.*Oracle HTTP Server.*", string:svrline ) )
  set_kb_item( name:"www/apache", value:TRUE );

if( egrep( pattern:"^Server:.*Stronghold.*", string:svrline ) )
  set_kb_item( name:"www/stronghold", value:TRUE );

if( egrep( pattern:"^Server:.*Stronghold.*", string:svrline ) )
  set_kb_item( name:"www/apache", value:TRUE );

if( egrep( pattern:"^Server:.*MiniServ.*", string:svrline ) )
  set_kb_item( name:"www/miniserv", value:TRUE );

if( egrep( pattern:"^Server:.*vqServer.*", string:svrline ) )
  set_kb_item( name:"www/vqserver", value:TRUE );

if( egrep( pattern:"^Server:.*VisualRoute.*", string:svrline ) )
  set_kb_item( name:"www/visualroute", value:TRUE );

if( egrep( pattern:"^Server:.*Squid.*", string:svrline ) )
  set_kb_item( name:"www/squid", value:TRUE );

if( egrep( pattern:"^Server:.*OmniHTTPd.*", string:svrline ) )
  set_kb_item( name:"www/omnihttpd", value:TRUE );

if( egrep( pattern:"^Server:.*linuxconf.*", string:svrline ) )
  set_kb_item( name:"www/linuxconf", value:TRUE );

if( egrep( pattern:"^Server:.*CompaqHTTPServer.*", string:svrline ) )
  set_kb_item( name:"www/compaq", value:TRUE );

if( egrep( pattern:"^Server:.*WebSTAR.*", string:svrline ) )
  set_kb_item( name:"www/webstar", value:TRUE );

if( egrep( pattern:"^Server:.*AppleShareIP.*", string:svrline ) )
  set_kb_item( name:"www/appleshareip", value:TRUE );

if( egrep( pattern:"^Server:.*Jigsaw.*", string:svrline ) )
  set_kb_item( name:"www/jigsaw", value:TRUE );

if( egrep( pattern:"^Server:.*Resin.*", string:svrline ) )
  set_kb_item( name:"www/resin", value:TRUE );

if( egrep( pattern:"^Server:.*AOLserver.*", string:svrline ) )
  set_kb_item( name:"www/aolserver", value:TRUE );

if( egrep( pattern:"^Server:.*IdeaWebServer.*", string:svrline ) )
  set_kb_item( name:"www/ideawebserver", value:TRUE );

if( egrep( pattern:"^Server:.*FileMakerPro.*", string:svrline ) )
  set_kb_item( name:"www/filemakerpro", value:TRUE );

if( egrep( pattern:"^Server:.*NetWare-Enterprise-Web-Server.*", string:svrline ) )
  set_kb_item( name:"www/netware", value:TRUE );

if( egrep( pattern:"^Server:.*Roxen.*", string:svrline ) )
  set_kb_item( name:"www/roxen", value:TRUE );

if( egrep( pattern:"^Server:.*SimpleServer:WWW.*", string:svrline ) )
  set_kb_item( name:"www/simpleserver", value:TRUE );

if( egrep( pattern:"^Server:.*Allegro-Software-RomPager.*", string:svrline ) )
  set_kb_item( name:"www/allegro", value:TRUE );

if( egrep( pattern:"^Server:.*GoAhead-Webs.*", string:svrline ) )
  set_kb_item( name:"www/goahead", value:TRUE );

if( egrep( pattern:"^Server:.*Xitami.*", string:svrline ) )
  set_kb_item( name:"www/xitami", value:TRUE );

if( egrep( pattern:"^Server:.*EmWeb.*", string:svrline ) )
  set_kb_item( name:"www/emweb", value:TRUE );

if( egrep( pattern:"^Server:.*Ipswitch-IMail.*", string:svrline ) )
  set_kb_item( name:"www/ipswitch-imail", value:TRUE );

if( egrep( pattern:"^Server:.*Netscape-FastTrack.*", string:svrline ) ) {
  set_kb_item( name:"www/netscape-fasttrack", value:TRUE );
  set_kb_item( name:"www/netscape_servers", value:TRUE );
}

if( egrep( pattern:"^Server:.*AkamaiGHost.*", string:svrline ) )
  set_kb_item( name:"www/akamaighost", value:TRUE );

if( egrep( pattern:"^Server:.*[aA]libaba.*", string:svrline ) )
  set_kb_item( name:"www/alibaba", value:TRUE );

if( egrep( pattern:"^Server:.*tigershark.*", string:svrline ) )
  set_kb_item( name:"www/tigershark", value:TRUE );

if( egrep( pattern:"^Server:.*Netscape-Commerce.*", string:svrline ) ) {
  set_kb_item( name:"www/netscape-commerce", value:TRUE );
  set_kb_item( name:"www/netscape_servers", value:TRUE );
}

if( egrep( pattern:"^Server:.*Oracle_Web_listener.*", string:svrline ) )
  set_kb_item( name:"www/oracle-web-listener", value:TRUE );

if( egrep( pattern:"^Server:.*Caudium.*", string:svrline ) )
  set_kb_item( name:"www/caudium", value:TRUE );

if( egrep( pattern:"^Server:.*Communique.*", string:svrline ) )
  set_kb_item( name:"www/communique", value:TRUE );

if( egrep( pattern:"^Server:.*Cougar.*", string:svrline ) )
  set_kb_item( name:"www/cougar", value:TRUE );

if( egrep( pattern:"^Server:.*FirstClass.*", string:svrline ) )
  set_kb_item( name:"www/firstclass", value:TRUE );

if( egrep( pattern:"^Server:.*NetCache.*", string:svrline ) )
  set_kb_item( name:"www/netcache", value:TRUE );

if( egrep( pattern:"^Server:.*AnWeb.*", string:svrline ) )
  set_kb_item( name:"www/anweb", value:TRUE );

if( egrep( pattern:"^Server:.*Pi3Web.*", string:svrline ) )
  set_kb_item( name:"www/pi3web", value:TRUE );

if( egrep( pattern:"^Server:.*TUX.*", string:svrline ) )
  set_kb_item( name:"www/tux", value:TRUE );

if( egrep( pattern:"^Server:.*Abyss.*", string:svrline ) )
  set_kb_item( name:"www/abyss", value:TRUE );

if( egrep( pattern:"^Server:.*BadBlue.*", string:svrline ) )
  set_kb_item( name:"www/badblue", value:TRUE );

if( egrep( pattern:"^Server:.*WebServer 4 Everyone.*", string:svrline ) )
  set_kb_item( name:"www/webserver4everyone", value:TRUE );

if( egrep( pattern:"^Server:.*KeyFocus Web Server.*", string:svrline ) ) {
  set_kb_item( name:"www/KFWebServer", value:TRUE );
  # TODO: Move into own Detection-NVT and catch the version
  register_and_report_cpe( app:"KeyFocus Web Server", insloc:port + "/tcp", regPort:port, concluded:svrline, base:"cpe:/a:key_focus:kf_web_server:", expr:"^([0-9.]+)" );
}

if( egrep( pattern:"^Server:.*Jetty.*", string:svrline ) )
  set_kb_item( name:"www/jetty", value:TRUE );

if( egrep( pattern:"^Server:.*bkhttp/.*", string:svrline ) )
  set_kb_item( name:"www/BitKeeper", value:TRUE );

if( egrep( pattern:"^Server:.*CUPS/.*", string:svrline ) )
  set_kb_item( name:"www/cups", value:TRUE );

if( egrep( pattern:"^Server:.*WebLogic.*", string:svrline ) )
  set_kb_item( name:"www/weblogic", value:TRUE );

if( egrep( pattern:"^Server:.*Novell-HTTP-Server.*", string:svrline ) )
  set_kb_item( name:"www/novell", value:TRUE );

if( egrep( pattern:"^Server:.*theServer/.*", string:svrline ) )
  set_kb_item( name:"www/theserver", value:TRUE );

if( egrep( pattern:"^Server:.*WWW File Share.*", string:svrline ) )
  set_kb_item( name:"www/wwwfileshare", value:TRUE );

#if(!egrep(pattern:"^Server:.*", string:svrline ) )
#  set_kb_item( name:"www/none", value:TRUE );

if( show_headers == "yes" ) report += '\n\nFull HTTP headers:\n\n' + res;
log_message( port:port, data:report );

exit( 0 );
