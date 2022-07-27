# OpenVAS Vulnerability Test
# Description: x-news 1
#
# Authors:
# Audun Larsen <larsen@xqus.com>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
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
#

if(description)
{
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_oid("1.3.6.1.4.1.25623.1.0.12068");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1656");
  script_bugtraq_id(4283);
  script_name("x-news 1");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Audun Larsen");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.ifrance.com/kitetoua/tuto/x_holes.txt");

  script_tag(name:"solution", value:"Deny access to the files in the 'db' directory through the webserver.");

  script_tag(name:"summary", value:"The remote web server is running X-News which is prone to
  information disclosure.");

  script_tag(name:"insight", value:"X-News stores user ids and passwords, as MD5 hashes, in a world-
  readable file, 'db/users.txt'. This is the same information that is
  issued by X-News in cookie-based authentication credentials.");

  script_tag(name:"impact", value:"An attacker may incorporate this information into cookies and then submit
  them to gain unauthorized access to the X-News administrative account.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/x-news", "/x_news", "/xnews", "/news", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  req = http_get(item:string(dir, "/x_news.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res)
    continue;

  if("Powered by <a href='http://www.xqus.com'>x-news</a> v.1\.[01]" >< res) {

    url = string(dir, "/db/users.txt");
    req2 = http_get(item:url, port:port);
    res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
    if(!res2)
      continue;

    if("|1" >< res2) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );