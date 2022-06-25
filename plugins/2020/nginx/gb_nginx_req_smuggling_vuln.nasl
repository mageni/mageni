# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143351");
  script_version("2020-01-14T04:01:37+0000");
  script_tag(name:"last_modification", value:"2020-01-14 04:01:37 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 03:57:07 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-20372");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx 0.7.12 < 1.17.7 HTTP Request Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"summary", value:"nginx, with certain error_page configurations, allows HTTP request smuggling,
  as demonstrated by the ability of an attacker to read unauthorized web pages in environments where nginx is
  being fronted by a load balancer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx versions 0.7.12 - 1.17.6.");

  script_tag(name:"solution", value:"Update to version 1.17.7 or later.");

  script_xref(name:"URL", value:"https://nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"https://bertjwregeer.keybase.pub/2019-12-10%20-%20error_page%20request%20smuggling.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "0.7.12", test_version2: "1.17.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.17.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
