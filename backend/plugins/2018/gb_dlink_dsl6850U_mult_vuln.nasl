###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl6850U_mult_vuln.nasl 8320 2018-01-08 10:06:11Z gveerendra $
#
# D-Link DSL-6850U Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/h:dlink:dsl-";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812376");
  script_version("$Revision: 8320 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 11:06:11 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 15:39:16 +0530 (Wed, 03 Jan 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("D-Link DSL-6850U Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running D-Link DSL-6850U router
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to access the administration or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,
  - Default account username:support and password:support and it cannot be disabled.
  - Availability of the shell interface although only a set of commands, but
    commands can be combined using logical AND , logical OR.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access administration of the device and execute arbitrary code
  on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"D-Link DSL-6850U versions BZ_1.00.01 - BZ_1.00.09");

  script_tag(name:"solution", value:"Apply the latest security patches from the
  vendor. For details refer to http://www.dlink.com/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://blogs.securiteam.com/index.php/archives/3588");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_detect.nasl");
  script_mandatory_keys("host_is_dlink_dsl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

dlinkPort = "";
model = "";
req = "";
res = "";

if(!dlinkPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!model = get_kb_item("Dlink/DSL/model")){
  exit(0);
}

if(model == "6850U")
{
  host = http_host_name( port:dlinkPort );
  ##Base64(support:support) == c3VwcG9ydDpzdXBwb3J0
  req = string( "GET /lainterface.html HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Authorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n", 
                "\r\n");
  res = http_keepalive_send_recv(port:dlinkPort, data:req);

  if(res && "WAN SETTINGS" >< res && "value='3G Interface" >< res && "menu.html" >< res
         && "TabHeader=th_setup" >< res && 'src="util.js"' >< res && 'src="language_en.js"' >< res)
  {
    report = report_vuln_url(port:dlinkPort, url:"/lainterface.html");
    security_message(port:dlinkPort, data:report);
    exit(0);
  }
}
exit(0);
