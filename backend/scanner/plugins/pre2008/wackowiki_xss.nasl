###############################################################################
# OpenVAS Vulnerability Test
# $Id: wackowiki_xss.nasl 9727 2018-05-04 09:12:47Z cfischer $
#
# WackoWiki XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14230");
  script_version("$Revision: 9727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 11:12:47 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2624");
  script_bugtraq_id(10860);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WackoWiki XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host seems to be running the WackoWiki CGI suite.

  Based on the version information gathered by OpenVAS  this instance
  of WackoWiki may be vulnerable to a remote authentication attack.");

  script_tag(name:"impact", value:"Exploitation of this vulnerability may allow for theft of cookie-based
  authentication credentials and cross-site scripting attacks.");

  script_tag(name:"solution", value:"Update or disable this CGI suite.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/WackoWiki";

  #Powered by WackoWiki R4.0
  if( http_vuln_check( port:port, url:url, pattern:"Powered by .*WackoWiki R3\.5", usecache:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
