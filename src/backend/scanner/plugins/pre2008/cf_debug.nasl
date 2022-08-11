###############################################################################
# OpenVAS Vulnerability Test
# $Id: cf_debug.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# ColdFusion Debug Mode
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
#
# Copyright:
# Copyright (C) 2001 Felix Huber
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
  script_oid("1.3.6.1.4.1.25623.1.0.10797");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ColdFusion Debug Mode");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Felix Huber");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Enter a IP (e.g. 127.0.0.1) in the Debug Settings
  within the ColdFusion Admin.");

  script_tag(name:"summary", value:"It is possible to see the ColdFusion Debug Information
  by appending ?Mode=debug at the end of the request (like GET /index.cfm?Mode=debug).

  4.5 and 5.0 are definitely concerned (probably in
  addition older versions).

  The Debug Information usually contain sensitive data such
  as Template Path or Server Version.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = make_list( "/", "/index.cfm", "/index.cfml", "/home.cfm",
                   "/home.cfml", "/default.cfml", "/default.cfm" );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file + "?Mode=debug";

    if( http_vuln_check( port:port, url:url, pattern:"CF_TEMPLATE_PATH" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );