##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# WampServer 'lang' Parameter Cross-site Scripting (XSS) Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:wampserver:wampserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800298");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(38357);
  script_cve_id("CVE-2010-0700");
  script_name("WampServer 'lang' Parameter Cross-site Scripting (XSS) Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wampserver/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38706");
  script_xref(name:"URL", value:"http://zeroscience.mk/codes/wamp_xss.txt");
  script_xref(name:"URL", value:"http://zeroscience.mk/en/vulnerabilities/ZSL-2010-4926.php");

  script_tag(name:"insight", value:"Input passed to the 'lang' parameter in index.php is not properly sanitised
  before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running WampServer is prone to Cross-Site Scripting
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected application.");
  script_tag(name:"affected", value:"WampServer version 2.0i");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php?lang=<script>alert('VT_XSS_Testing')</script>";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "<script>alert('VT_XSS_Testing')</script>" >< rcvRes && rcvRes =~ "HTTP/1\.. 200" ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );