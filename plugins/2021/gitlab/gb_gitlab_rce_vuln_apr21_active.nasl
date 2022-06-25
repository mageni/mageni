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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147118");
  script_version("2021-11-09T14:03:25+0000");
  script_tag(name:"last_modification", value:"2021-11-09 14:03:25 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-08 08:00:48 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-30 19:37:00 +0000 (Fri, 30 Apr 2021)");

  script_cve_id("CVE-2021-22205");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab < 13.8.8, 13.9.x < 13.9.6, 13.10.x < 13.10.3 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_http_detect.nasl");
  script_mandatory_keys("gitlab/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"GitLab is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been discovered in GitLab CE/EE. GitLab was not
  properly validating image files that were passed to a file parser which resulted in a remote
  command execution.");

  script_tag(name:"affected", value:"GitLab prior to version 13.8.8, 13.9.x through 13.9.5 and
  13.10.x through 13.10.2.");

  script_tag(name:"solution", value:"Update to version 13.8.8, 13.9.6, 13.10.3 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab/-/issues/327121");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/164768/GitLab-Unauthenticated-Remote-ExifTool-Command-Injection.html");
  script_xref(name:"URL", value:"https://attackerkb.com/topics/D41jRUXCiJ/cve-2021-22205/rapid7-analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
bound = '_' + vt_strings["default_rand"];
file = vt_strings["default"] + rand();

url = "/" + rand_str(length: 8, charset: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");

headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

data = '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="file"; filename="' + file + '.jpg"\r\n' +
       'Content-Type: image/jpeg\r\n' +
       'Content-Transfer-Encoding: binary\r\n\r\n' +
       rand_str(length: 32, charset: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz") + '\r\n' +
       '--' + bound + '--\r\n';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 422" && "The change you requested was rejected" >< res) {
  info['HTTP Method'] = "POST";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;
  info['HTTP "Content-Type" header'] = headers["Content-Type"];

  report  = 'The error response to the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'indicates that the host is not patched.';
  report += '\n\nResult (truncated):\n\n' + substr(res, 0, 800);
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(0);
