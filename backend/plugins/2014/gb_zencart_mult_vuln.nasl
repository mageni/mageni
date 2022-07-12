# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:zen-cart:zen_cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903513");
  script_version("2021-10-13T07:23:52+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-02-25 13:05:23 +0530 (Tue, 25 Feb 2014)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zen Cart Multiple Vulnerabilities (Feb 2014)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zencart_http_detect.nasl");
  script_mandatory_keys("zen_cart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Zen Cart is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Error which fails to sanitize 'redirect' parameter properly.

  - Insufficient validation of user-supplied input via the multiple POST parameters to multiple pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the
  context of an affected site and also can conduct phishing attacks.");

  script_tag(name:"affected", value:"Zen Cart version 1.5.1 and probably prior.");

  script_tag(name:"solution", value:"Vendor fixes are available.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125383/zencart151-shellxss.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/zen-cart-e-commerce-151-xss-open-redirect-shell-upload");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("smtp_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

domain = get_3rdparty_domain();

url = dir + "/index.php?main_page=redirect&action=url&goto=" + domain;

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res && res =~ "^HTTP/1\.[01] 302" && res =~ "Location\s*:\s+https?://" + domain) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
