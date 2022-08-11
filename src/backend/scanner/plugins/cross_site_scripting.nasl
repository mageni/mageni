###############################################################################
# OpenVAS Vulnerability Test
# $Id: cross_site_scripting.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Description: Web Server Cross Site Scripting
#
# Authors:
# SecuriTeam (code was the "40x_cross_site.nasl")
# modified by CIRT.net (sq@cirt.net) (with help from SecuriTeam) to check
# for multiple cross site scripting vuls.
# Update by Felix Huber - huberfelix@webtopia.de - 14.11.2001
# Update by Chris Sullo - sq@cirt.net - 16.11.2001
# false positive fix by Andrew Hintz - http://guh.nu - 1.3.2002
# Update by rd: thanks to Andrew's remarks, HTTP headers are discared
# Update by Chris Sullo - sq@cirt.net - 06/27/2002 -- added .cfm test
#
# Copyright:
# Copyright (C) 2001 SecuriTeam, modified by Chris Sullo and Andrew Hintz
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
  script_oid("1.3.6.1.4.1.25623.1.0.10815");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Web Server Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2001 SecuriTeam, modified by Chris Sullo and Andrew Hintz");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/Security_concerns_when_developing_a_dynamically_generated_web_site.html");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2000-02.html");

  script_tag(name:"summary", value:"The remote web server seems to be vulnerable to a Cross Site Scripting
  vulnerability (XSS). The vulnerability is caused by the result being returned to the user when a non-existing
  file is requested (e.g. the result contains script code provided in the request).");

  script_tag(name:"impact", value:"This vulnerability would allow an attacker to make the server present the
  user with the attacker's JavaScript/HTML code.

  Since the content is presented by the server, the user will give it the trust level of the server (for example,
  the websites banks, shopping centers, etc. would usually be trusted by a user).");

  script_tag(name:"solution", value:"See the references for various background information.");

  script_tag(name:"qod", value:"50"); # Vuln check below is quite unreliable these days...
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

post[0] = ".jsp";
post[1] = ".shtml";
post[2] = ".thtml";
post[3] = ".cfm";
post[4] = ".php";
post[5] = "";
post[6] = "";
post[7] = "";
post[8] = "";
post[9] = "";
post[10] = "";

dir[0] = ".jsp";
dir[1] = ".shtml";
dir[2] = ".thtml";
dir[3] = ".cfm";
dir[4] = ".php";
dir[5] = "MAGIC";
dir[6] = ".jsp";
dir[7] = ".shtml";
dir[8] = ".thtml";
dir[9] = ".cfm";
dir[10] = ".php";

confirmtext = "<SCRIPT>foo</SCRIPT>";

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

for( i = 0; dir[i]; i++ ) {
  if ( dir[i] == "MAGIC" )
    url = "/" + confirmtext;
  else
    url = "/foo" + dir[i] + "?param=" + confirmtext + post[i];

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( res =~ "^HTTP/1\.[01] 200" && confirmtext >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    http_set_has_generic_xss( port:port, host:host );
    exit( 0 );
  }
}

exit( 99 );