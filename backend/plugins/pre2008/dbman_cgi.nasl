###############################################################################
# OpenVAS Vulnerability Test
# $Id: dbman_cgi.nasl 10122 2018-06-07 13:09:58Z cfischer $
#
# DBMan CGI server information leakage
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10403");
  script_version("$Revision: 10122 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 15:09:58 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1178);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2000-0381");
  script_name("DBMan CGI server information leakage");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version");

  script_tag(name:"summary", value:"It is possible to cause the DBMan
  CGI to reveal sensitive information, by requesting a URL such as:

  GET /scripts/dbman/db.cgi?db=no-db");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

req = http_get( item:"/scripts/dbman/db.cgi?db=no-db", port:port );
result = http_send_recv( port:port, data:req );
backup = result;
report = string( "\nIt is possible to cause the DBMan\nCGI to reveal sensitive information, by requesting a URL such as:\n\n",
"GET /scripts/dbman/db.cgi?db=no-db\n\nWe could obtain the following : \n\n");

if( "CGI ERROR" >< result ) {
  result = strstr(backup, string("name: no-db at "));
  result = result - strstr(result, string(" line "));
  result = result - "name: no-db at ";
  report = "CGI full path is at: " + result + string("\n");

  result = strstr(backup, string("Perl Version        : "));
  result = result - strstr(result, string("\n"));
  result = result - string("Perl Version        : ");
  report = report + "Perl version: " + result + string("\n");

  result = strstr(backup, string("PATH                : "));
  result = result - strstr(result, string("\n"));
  result = result - string("PATH                : ");
  report = report + "Server path: " + result + string("\n");

  result = strstr(backup, string("SERVER_ADDR         : "));
  result = result - strstr(result, string("\n"));
  result = result - string("SERVER_ADDR         : ");
  report = report + "Server real IP: " + result + string("\n");

  result = strstr(backup, string("SERVER_SOFTWARE     : "));
  result = result - strstr(result, string("\n"));
  result = result - string("SERVER_SOFTWARE     : ");
  report = report + "Server software: " + result + string("\n");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );