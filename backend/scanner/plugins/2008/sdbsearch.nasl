###################################################################
# OpenVAS Vulnerability Test
# $Id: sdbsearch.nasl 4489 2016-11-14 08:23:54Z teissa $
#
# sdbsearch.cgi
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2004 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80084");
  script_version("$Revision: 4489 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 09:23:54 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1130");
  script_name("sdbsearch.cgi");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Modify the script so that it filters
  the HTTP_REFERRER variable, or delete it.");
  script_tag(name:"summary", value:"The SuSE cgi 'sdbsearch.cgi' is installed.
  This cgi allows a local (and possibly remote) user to execute arbitrary
  commands with the privileges of the HTTP server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/sdbsearch.cgi?stichwort=anything";

  req = string( "GET ", url, " HTTP/1.1\r\n",
                "Referer: http://", host, "/../../../../etc\r\n",
                "Host: ", host, "\r\n\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "htdocs//../../../../etc/keylist.txt" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );