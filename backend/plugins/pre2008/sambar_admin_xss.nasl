###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_admin_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Sambar Server Administrative Interface multiple XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

#  Ref: jamie fisher <contact_jamie_fisher@yahoo.co.uk>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18364");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(13722);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Sambar Server Administrative Interface multiple XSS");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  script_tag(name:"solution", value:"Upgrade at least to version 6.2.1.");

  script_tag(name:"summary", value:"The remote host runs the Sambar web server.

  The remote version of this software is vulnerable to multiple cross site
  scripting attacks.

  With a specially crafted URL, an attacker can use the remote host to perform
  a cross site scripting against a third party.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, '/search/results.stm?indexname=>"><script>foo</script>&style=fancy&spage=60&query=Folder%20name' );

  #<FONT SIZE="+3">S</FONT>AMBAR
  #<FONT SIZE="+3">S</FONT>EARCH
  #<FONT SIZE="+3">E</FONT>NGINE</H2>

  if( http_vuln_check( port:port, url:url, pattern:">S</FONT>AMBAR", extra_check:"<script>foo</script>", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
