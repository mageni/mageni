###############################################################################
# OpenVAS Vulnerability Test
# $Id: aardvark_topsites_multiple.nasl 9727 2018-05-04 09:12:47Z cfischer $
#
# Aardvark Topsites Multiple Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# From: JeiAr [security@gulftech.org]
# Subject: Aardvark Topsites 4.1.0 Vulnerabilities
# Date: Tuesday 16/12/2003 04:58

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11957");
  script_version("$Revision: 9727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 11:12:47 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9231);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Aardvark Topsites Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 4.1.1 or newer.");

  script_tag(name:"summary", value:"Aardvark Topsites is a popular free PHP Topsites script.
  Multiple vulnerabilities have been found in the product allowing remote attacker to
  disclosure sensitive information about the server and inject malicious SQL statements.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";

  if( http_vuln_check( port:port, url:url, pattern:"Aardvark Topsites PHP.* (4\.1\.0|4\.0\.|[0-3]\..*)", usecache:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );