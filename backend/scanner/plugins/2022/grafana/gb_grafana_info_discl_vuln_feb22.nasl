# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147825");
  script_version("2022-03-22T07:43:05+0000");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 03:18:32 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2022-26148");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Grafana Information Disclosure Vulnerability (Feb 2022) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/http/detected");
  script_require_ports("Services/www", 3000);

  script_tag(name:"summary", value:"Grafana is prone to an information disclosure vulnerability
  when integrated with Zabbix.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"The Zabbix password can be found in the api_jsonrpc.php HTML
  source code. When the user logs in and allows the user to register, one can right click to view
  the source code and use Ctrl-F to search for password in api_jsonrpc.php to discover the Zabbix
  account password and URL address.");

  script_tag(name:"solution", value:"No known solution is available as of 22nd March, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://2k8.org/post-319.html");

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

url = dir + "/";

pattern = '"password":"[^"]+"';
if (res = http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE,
                          icase: FALSE, extra_check: '"name":"Zabbix"')) {
  report = http_report_vuln_url(port: port, url: url);
  pwd = eregmatch(string: res, pattern: pattern, icase: FALSE);
  if (pwd)
    report += '\nExtracted Password: ' + pwd[0];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
