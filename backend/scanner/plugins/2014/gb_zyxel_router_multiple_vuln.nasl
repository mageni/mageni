###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_router_multiple_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# ZyXEL ADSL Router Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804471");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-06-25 12:28:41 +0530 (Wed, 25 Jun 2014)");
  script_name("ZyXEL ADSL Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running ZyXEL ADSL Router and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to read cookie or not.");
  script_tag(name:"insight", value:"- The 'Forms/rpAuth_1' does not validate input to an arbitrary parameter
    before returning it to users.

  - ZyXEL contains a flaw that is due to a lack of protection mechanisms in
    the login form.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");
  script_tag(name:"affected", value:"ZyXEL P660RT2 EE");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127179");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/103");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

zPort = get_http_port(default:80);

zBanner = get_http_banner(port:zPort);
if('Server: RomPager' >!< zBanner) exit(0);

url ="/Forms/rpAuth_1?=%3Cbody%20onload=alert%28document.cookie%29%3E";

if(http_vuln_check(port:zPort, url:url, check_header:TRUE,
   pattern: "<body onload=alert\(document.cookie\)><",
   extra_check:"> Message <"))
{
  security_message(port:zPort);
  exit(0);
}

exit(99);
