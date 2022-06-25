###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle_xsql.nasl 12621 2018-12-03 10:50:25Z cfischer $
#
# Oracle XSQL Stylesheet Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10594");
  script_version("$Revision: 12621 $");
  script_cve_id("CVE-2001-0126");
  script_bugtraq_id(2295);
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 11:50:25 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle XSQL Stylesheet Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Oracle/banner"); # The check below is quite unreliable these days so just run it against Oracle servers

  script_tag(name:"summary", value:"The Oracle XSQL Servlet allows arbitrary Java code to be executed by an attacker by supplying
  the URL of a malicious XSLT stylesheet when making a request to an XSQL page.");
  script_tag(name:"solution", value:"Until Oracle changes the default behavior for the XSQL servlet to disallow client supplied stylesheets,
  you can workaround this problem as follows. Add allow-client-style='no' on the document element of every xsql page on
  your server.

  This plug-in tests for this vulnerability using a sample page, airport.xsql, which is supplied with the Oracle XSQL
  servlet. Sample code should always be removed from production servers.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/xsql/demo/airport/airport.xsql?xml-stylesheet=none";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" && "cvsroot" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );