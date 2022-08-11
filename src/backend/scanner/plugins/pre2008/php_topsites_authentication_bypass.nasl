###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_topsites_authentication_bypass.nasl 9727 2018-05-04 09:12:47Z cfischer $
#
# Multiple vulnerabilities in PHP TopSites
#
# Authors:
# Josh Zlatin-Amishav
# Fixes by Tenable:
#   - Fixed script name.
#   - Removed unnecessary include of url_func.inc.
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19495");
  script_version("$Revision: 9727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 11:12:47 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(14353);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Multiple vulnerabilities in PHP TopSites");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Limit access to admin directory using, eg, .htaccess.");

  script_tag(name:"summary", value:"The remote host is running PHP TopSites, a PHP/MySQL-based
  customizable TopList script.

  There is a vulnerability in this software which allows an attacker to
  access the admin/setup interface without authentication.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/admin/setup.php";

  if( http_vuln_check( port:port, url:url, pattern:"<title>PHP TopSites", extra_check:"function mMOver\(ob\)", usecache:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
