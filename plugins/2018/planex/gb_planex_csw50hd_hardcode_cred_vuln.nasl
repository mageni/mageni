###############################################################################
# OpenVAS Vulnerability Test
#
# PLANEX CS-W50HD Hardcode Credential Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/h:planex:ip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813883");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-12574");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-03 15:43:26 +0530 (Mon, 03 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("PLANEX CS-W50HD Hardcode Credential Vulnerability");

  script_tag(name:"summary", value:"This host is installed with PLANEX CS-W50HD
  network camera and is prone to hardcode credential vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"The flaw exists due to hardcoded credential
  'supervisor:dangerous' which are injected into web authentication database
  '/.htpasswd' during booting process.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain unauthorized access and control the device completely,
  the account can't be modified or deleted.");

  script_tag(name:"affected", value:"PLANEX CS-W50HD devices with firmware before 030720");

  script_tag(name:"solution", value:"Upgrade to firmware version 030720 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Aug/25");
  script_xref(name:"URL", value:"https://www.planex.co.jp/products/cs-w50hd");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!plxPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:plxPort)) exit(0);

auth = 'Basic ' + base64(str:'supervisor:dangerous');
req = http_get_req(port: plxPort, url: dir + "cgi-bin/info.cgi", add_headers: make_array("Authorization", auth));
res = http_keepalive_send_recv( port: plxPort, data: req );

if(res =~ "^HTTP/1\.[01] 200 OK" && "IP CAM Information" >< res && "CS-W50HD" >< res &&
   "WiFi Mac Address" >< res && "Network type" >< res && "IP CAM ID" >< res)
{
  report = 'It was possible to login into the Web management UI at ' +
           report_vuln_url(port:plxPort, url:'/cgi-bin/info.cgi', url_only:TRUE) +
           ' using supervisor:dangerous as credentials.\r\n';
  security_message(port:plxPort, data:report);
  exit(0);
}
exit(0);
