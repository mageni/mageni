# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114133");
  script_version("2019-09-27T11:27:33+0000");
  script_tag(name:"last_modification", value:"2019-09-27 11:27:33 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-23 15:56:48 +0200 (Mon, 23 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-16645");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("GoAhead Server HTTP Header Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to an HTTP header injection vulnerability.");

  script_tag(name:"insight", value:"For certain pages, Embedthis GoAhead creates links containing a hostname
  obtained from an arbitrary HTTP Host header sent by an attacker.");

  script_tag(name:"impact", value:"An attacker can potentially use this vulnerability in a phishing attack.");

  script_tag(name:"vuldetect", value:"Checks if such a manipulated link can be created.");

  script_tag(name:"affected", value:"At least GoAhead version 2.5.0.");

  script_tag(name:"solution", value:"No known solution is available as of 27th September, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Ramikan/Vulnerabilities/blob/master/GoAhead%20Web%20server%20HTTP%20Header%20Injection");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if(! banner || "GoAhead-" >!< banner)
  exit(0);

vuln_urls = make_array();

poc_urls = make_list(
  "/goform/login", #POC: 1
  "/config/log_off_page.htm", #POC: 2
  "/"); #POC: 3

foreach poc_url (poc_urls) {

  vt_strings = get_vt_strings();
  host_header = vt_strings["lowercase_rand"];

  req = http_post_req(port: port, url: poc_url, data: "testdata");
  req = ereg_replace(string: req, pattern: '(Host: [^\r\n]+)', replace: "Host: " + host_header);
  res = http_keepalive_send_recv(port: port, data: req);
  if(!res)
    continue;

  if(match = egrep(string: res, pattern: "(^Location:|This document has moved to a new).+" + host_header, icase: TRUE)) {
    vuln_urls[poc_url] = chomp(match);
    VULN = TRUE;
  }
}

if(VULN) {
  report = "It was possible to inject a host header and create a manipulated link via a HTTP POST-request to:";
  foreach vuln_url (keys(vuln_urls)) {
    report += '\n\nURL:         ' + report_vuln_url(port: port, url: vuln_url, url_only: TRUE);
    report += '\nResponse(s): ' + vuln_urls[vuln_url];
  }
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
