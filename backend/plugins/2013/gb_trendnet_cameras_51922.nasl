###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_cameras_51922.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Multiple Trendnet Camera Products Remote Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103791");
  script_bugtraq_id(51922);
  script_version("$Revision: 14117 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Multiple Trendnet Camera Products Remote Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51922");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36680");
  script_xref(name:"URL", value:"http://www.trendnet.com/press/view.asp?id=1959");
  script_xref(name:"URL", value:"http://www.trendnet.com/products/proddetail.asp?prod=145_TV-IP110W");
  script_xref(name:"URL", value:"http://console-cowboys.blogspot.com.au/2012/01/trendnet-cameras-i-always-feel-like.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-19 18:42:42 +0200 (Thu, 19 Sep 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netcam/banner");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow remote attackers to gain
  access to a live stream from the camera.");

  script_tag(name:"vuldetect", value:"Test if it is possible to access /anony/mjpg.cgi without authentication");

  script_tag(name:"insight", value:"On vulnerable devices it is possible to access the livestream
  without any authentication by requesting http://example.com/anony/mjpg.cgi.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple Trendnet Camera products are prone to a remote security-
  bypass vulnerability.");

  script_tag(name:"affected", value:"TV-VS1P V1.0R 0, TV-VS1 1.0R 0, TV-IP422WN V1.0R 0, TV-IP422W A1.0R 0, TV-IP422 A1.0R 0,
  TV-IP410WN 1.0R 0, TV-IP410W A1.0R 0, TV-IP410 A1.0R 0, TV-IP322P 1.0R 0, TV-IP312WN 1.0R 0, TV-IP312W A1.0R 0, TV-IP312 A1.0R 0,
  TV-IP252P B1.xR 0, TV-IP212W A1.0R 0, TV-IP212 A1.0R 0, TV-IP121WN v2.0R 0, TV-IP121WN 1.0R 0, TV-IP121W A1.0R 0, TV-IP110WN 2.0R 0,
  TV-IP110WN 1.0R, TV-IP110W A1.0R 0, TV-IP110 A1.0R 0.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("401 Unauthorized" >!< banner || 'Basic realm="netcam"' >!< banner)exit(0);

req = 'GET /anony/mjpg.cgi HTTP/1.0\r\n\r\n';
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 200 OK" && "x-mixed-replace" >< buf && "image/jpeg" >< buf) {
  report = report_vuln_url(port:port, url:"/anony/mjpg.cgi");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);