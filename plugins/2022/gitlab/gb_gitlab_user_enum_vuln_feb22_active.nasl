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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117992");
  script_version("2022-03-04T09:04:02+0000");
  script_tag(name:"last_modification", value:"2022-03-04 10:35:15 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-04 06:52:21 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-4191");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 13.0.x < 14.6.5, 14.4.x < 14.7.4, 14.8.x < 14.8.2 GraphQL API User Enumeration Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO); # nb: Normal API request so no ACT_ATTACK

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_http_detect.nasl");
  script_mandatory_keys("gitlab/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"GitLab is prone to a user enumeration vulnerability via the
  GraphQL API.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"An issue has been discovered in GitLab CE/EE. Private GitLab
  instances with restricted sign-ups may be vulnerable to user enumeration by unauthenticated users
  through the GraphQL API.");

  script_tag(name:"affected", value:"GitLab in all versions starting from 13.0 and all versions
  starting from 14.4 before 14.8 with restricted sign-ups.");

  script_tag(name:"solution", value:"Update to version 14.6.5, 14.7.4, 14.8.2 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/02/25/critical-security-release-gitlab-14-8-2-released/#unauthenticated-user-enumeration-on-graphql-api");
  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/2022/03/03/cve-2021-4191-gitlab-graphql-api-user-enumeration-fixed/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "")
  dir = "";

url = "/api/graphql";

headers = make_array("Content-Type", "application/json");

data = '{"query":"query{users{nodes{username}}}"}';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);
if (!res || res !~ "^HTTP/1\.[01] 200" || res !~ "Content-Type\s*:\s*application/json")
  exit(0);

body = http_extract_body_from_response(data: res);
if (!body)
  exit(0);

# e.g.
# {"data":{"users":{"nodes":[{"username":"user1"},{"username":"user2"},
if (body =~ '\\{"data"\\s*:\\s*\\{"users"\\s*:\\s*\\{.+\\{"username"\\s*:\\s*"[^"]+"\\}') {

  # nb: body might have a trailing newline, remove that for the reporting below.
  body = ereg_replace(string: body, pattern: "^(\s+)", replace: "");

  info["HTTP Method"] = "POST";
  info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;
  info['HTTP "Content-Type" header'] = headers["Content-Type"];

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to enumerate existing users.';
  report += '\n\nResult (truncated):\n\n' + substr(body, 0, 800);
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

# nb: No exit(99); as the system might not have restricted sign-ups enabled
exit(0);
