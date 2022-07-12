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

CPE = "cpe:/a:lucee:lucee_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146116");
  script_version("2021-06-11T10:00:57+0000");
  script_tag(name:"last_modification", value:"2021-06-14 10:28:51 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-11 09:21:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-21307");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lucee < 5.3.5.96, 5.3.6.x < 5.3.6.68, 5.3.7.x < 5.3.7.47 RCE Vulnerability (GHSA-2xvv-723c-8p7r) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lucee_http_detect.nasl");
  script_mandatory_keys("lucee/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Lucee is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"In Lucee Admin there is an unauthenticated RCE vulnerability.

  Note: If access to the Lucee Administrator is blocked the vulnerability is not exploitable.");

  script_tag(name:"affected", value:"Lucee version 5.3.5.96 and prior, 5.3.6.x through 5.3.6.67 and
  5.3.7.x through 5.3.7.46.");

  script_tag(name:"solution", value:"Update to version 5.3.5.96, 5.3.6.68, 5.3.7.47 or later.");

  script_xref(name:"URL", value:"https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r");
  script_xref(name:"URL", value:"https://github.com/httpvoid/writeups/blob/main/Apple-RCE.md");

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

# Seems to be available only on newer versions
url = "/lucee/admin/imgProcess.cfm?file=harsh.cfm";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

data = "imgSrc=";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

# Patched versions return a 404 response
if (res =~ "^HTTP/1\.[01] 200") {
  info['HTTP Method'] = "POST";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;
  info['HTTP "Content-Type" header'] = headers["Content-Type"];

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'the response indicates that the resource is accessible.';
  report += '\n\nResult:\n\n' + res;
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(0);
