###############################################################################
# OpenVAS Vulnerability Test
# $Id: cern_httpd_access_ctrl.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# CERN HTTPD access control bypass
#
# Authors:
# Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.17230");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CERN HTTPD access control bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/content/auth_required");

  script_tag(name:"solution", value:"Upgrade your web server or tighten your filtering rules.

  A workaround consisted in rejecting patterns like:

  //*

  *//*

  /./*

  */./*");

  script_tag(name:"summary", value:"It is possible to access protected web pages
  by changing / with // or /./

  This was a bug in old versions of CERN web server.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function check( port, url ) {

  local_var port, url, no404, req, res;

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) exit( 0 );
  if( res =~ "^HTTP/[0-9]\.[0-9] +40[13]" ) {
    return 403;
  } else if( res =~ "^HTTP/[0-9]\.[0-9] +200 " ) {
    if( no404 && no404 >< res )
      return 404;
    else
      return 200;
  } else {
    return;
  }
}

port  = get_http_port( default:80 );
host  = http_host_name( dont_add_port:TRUE );
no404 = http_get_no404_string( port:port, host:host );

dirs = http_get_kb_auth_required( port:port, host:host );
if( isnull( dirs ) ) exit( 0 );

foreach dir( dirs ) {

  if( check( port:port, url:dir, no404:no404 ) == 403 ) {
    foreach pat( make_list( "//", "/./" ) ) {
      dir2 = ereg_replace( pattern:"^/", replace:pat, string:dir );
      if( check( port:port, url:dir2, no404:no404 ) == 200 ) {
        report = report_vuln_url( port:port, url:dir2 );
        security_message( port:port, data:report );
        exit( 0 );
      }

      dir2 = ereg_replace( pattern: "^(.+)/", replace:"\\1" + pat, string:dir );
      if( check( port:port, url:dir2 ) == 200) {
        report = report_vuln_url( port:port, url:dir2 );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );