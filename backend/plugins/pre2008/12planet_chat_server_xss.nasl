###############################################################################
# OpenVAS Vulnerability Test
# $Id: 12planet_chat_server_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# 12Planet Chat Server one2planet.infolet.InfoServlet XSS
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# From: "Donato Ferrante" <fdonato@autistici.org>
# Date: 5.7.2004 10:54
# XSS in 12Planet Chat Server 2.9

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12299");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0678");
  script_bugtraq_id(10659);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("12Planet Chat Server one2planet.infolet.InfoServlet XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker may use this bug to steal the credentials of the legitimate users
  of this site.");
  script_tag(name:"solution", value:"Upgrade to the newest version of this software");
  script_tag(name:"summary", value:"The remote host contains the 12Planet Chat Server CGI which is
  vulnerable to a cross-site scripting issue.

  There is a bug in this software which makes it vulnerable to cross site scripting attacks.");

  script_tag(name:"qod", value:"50"); # Prone to false positives
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/servlet/one2planet.infolet.InfoServlet?page=<script>foo</script>";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>foo</script>" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
