###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnr2000_router_multiple_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# NETGEAR WNR2000 Router Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:netgear:wnr2000";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809775");
  script_version("$Revision: 14117 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-30 15:20:48 +0530 (Fri, 30 Dec 2016)");

  script_cve_id("CVE-2016-10175", "CVE-2016-10176", "CVE-2016-10174");

  script_tag(name:"qod_type", value:"remote_active");
  script_name("NETGEAR WNR2000 Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running NETGEAR WNR2000 Router
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The device leaks its serial number while requesting for
    'BRS_netgear_success.html'.

  - Improper access control while sending request to 'apply_noauth.cgi'.

  - Timestamps used in application can be easily calculated and generated outside.

  - Improper handling of access to *.cgi files by HTTP server in the device (uhttpd).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, reboot router,
  factory reset the router, change WLAN settings, change password recovery settings,
  obtain the admin password once recovery settings are changed, execute code and
  conduct denial of service attack.");

  script_tag(name:"affected", value:"NETGEAR WNR2000 routers");

  script_tag(name:"solution", value:"NETGEAR has released beta firmware for the affected routers, which can be obtained from the referenced vendor KB entry.");

  script_xref(name:"URL", value:"http://kb.netgear.com/000036549/Insecure-Remote-Access-and-Command-Execution-Security-Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Dec/72");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/pedrib/PoC/master/advisories/netgear-wnr2000.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_wnr2000_router_detect.nasl");
  script_mandatory_keys("netgear_wnr2000/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!netPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/BRS_netgear_success.html";

req = http_get(item: url, port:netPort);
rcvRes = http_keepalive_send_recv(port:netPort, data:req);

if(rcvRes =~ "HTTP/1.. 200" && "wnr2000" >< rcvRes && "netgear" >< rcvRes)
{
  serial = eregmatch(pattern:'var sn="([0-9A-Za-z]+)";', string:rcvRes);
  if(serial[1])
  {
    report = report_vuln_url(port:netPort, url:url);
    security_message( port:netPort, data:report);
    exit(0);
  }
}
exit(0);