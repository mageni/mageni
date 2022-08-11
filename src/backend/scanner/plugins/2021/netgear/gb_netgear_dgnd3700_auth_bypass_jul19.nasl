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

CPE = "cpe:/o:netgear:dgnd3700_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117531");
  script_version("2021-07-05T07:37:07+0000");
  script_tag(name:"last_modification", value:"2021-07-06 10:39:30 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-02 12:12:38 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-17373");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("NETGEAR DGND3700 Authentication Bypass Vulnerability (Dec 2020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_dgnd3700_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("netgear/dgnd3700/http/detected");

  script_tag(name:"summary", value:"NETGEAR DGN3700 devices are prone to an authentication bypass
  vulnerability.");

  script_tag(name:"insight", value:"A flaw exists which allows accessing router management pages
  using an authentication bypass.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker might access or read sensitive
  information which could lead to a full compromise of the router.");

  script_tag(name:"affected", value:"NETGEAR DGND3700 devices in unknown firmware versions.");

  script_tag(name:"solution", value:"No known solution is available as of 02nd July, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/WAN_wan.htm";
# nb: False positive check if the file is accessible directly for some reason.
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
if (!res || res !~ "^HTTP/1\.[01] 401")
  exit(0);

url += "?pic.gif";

# nb: Some systems only responded on a second request with the expected data according to:
# https://github.com/projectdiscovery/nuclei-templates/pull/1839
req = http_get(port: port, item: url);
http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (http_vuln_check(port: port, url: url, pattern: "<title>WAN Setup", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);