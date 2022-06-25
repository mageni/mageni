###############################################################################
# OpenVAS Vulnerability Test
# $Id: rsa_authentication_agent_xss.nasl 11999 2018-10-21 09:01:06Z cfischer $
#
# RSA Security RSA Authentication Agent For Web XSS
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

#  ref : Oliver Karow <oliver.karow@gmx.de>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18213");
  script_version("$Revision: 11999 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 11:01:06 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1118");
  script_bugtraq_id(13168);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RSA Security RSA Authentication Agent For Web XSS");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgraded to version 5.3 or newer.");

  script_tag(name:"summary", value:"The remote host seems to be running the RSA Security RSA Authentication
  Agent for web.

  The remote version of this software is contains an input validation
  flaw in the 'postdata' variable. An attacker may use it to perform a
  cross site scripting attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = '/WebID/IISWebAgentIF.dll?postdata="><script>foo</script>';
req = http_get( item:url, port:port);
res = http_keepalive_send_recv( port:port, data:req );
if( ! res ) exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && "<TITLE>RSA SecurID " >< res && ereg( pattern:"<script>foo</script>", string:res ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
}

exit( 0 );