###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle_xsql_query.nasl 12621 2018-12-03 10:50:25Z cfischer $
#
# Oracle XSQL Sample Application Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to www.kb.cert.org
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10613");
  script_version("$Revision: 12621 $");
  script_cve_id("CVE-2002-1630", "CVE-2002-1631", "CVE-2002-1632");
  script_bugtraq_id(6556);
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 11:50:25 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle XSQL Sample Application Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Oracle/banner"); # The check below is quite unreliable these days so just run it against Oracle servers

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/717827");

  script_tag(name:"summary", value:"One of the sample applications that comes with
  the Oracle XSQL Servlet allows an attacker to make arbitrary queries to
  the Oracle database (under an unprivileged account).");
  script_tag(name:"impact", value:"Whilst not allowing an attacker to delete or modify database
  contents, this flaw can be used to enumerate database users and view table names.");
  script_tag(name:"solution", value:"Sample applications should always be removed from
  production servers.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/xsql/demo/adhocsql/query.xsql?sql=select%20username%20from%20ALL_USERS";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" && "USERNAME" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );