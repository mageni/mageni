###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle9i_isqlplus_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Oracle 9iAS iSQLplus XSS
#
# Authors:
# Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# Copyright:
# Copyright (C) 2004 Frank Berger
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

# This vulnerability was found by
# Rafel Ivgi, The-Insider <theinsider@012.net.il>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12112");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Oracle 9iAS iSQLplus XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 Frank Berger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/OracleApache");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2004/Jan/1008838.html");
  script_tag(name:"summary", value:"The login-page of Oracle9i iSQLplus allows the injection of HTML and Javascript
code via the username and password parameters.

Description :

The remote host is running a version of the Oracle9i 'isqlplus' CGI which
is vulnerable to a cross site scripting issue.

An attacker may exploit this flaw to to steal the cookies of legitimate
users on the remote host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
 of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
 disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

 req = http_get(item:"/isqlplus?action=logon&username=foo%22<script>foo</script>&password=test", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( isnull( res ) ) exit( 0 );
 if( res =~ "^HTTP/1\.[01] 200" && '<script>foo</script>' >< res )
 	security_message(port);
