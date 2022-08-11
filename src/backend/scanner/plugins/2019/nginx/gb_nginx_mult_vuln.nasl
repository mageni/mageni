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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142802");
  script_version("2019-08-27T05:04:04+0000");
  script_tag(name:"last_modification", value:"2019-08-27 05:04:04 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 04:48:10 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx HTTP/2 Multiple Vulnerablilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"summary", value:"nginx is prone to multiple denial of service vulnerabilities in the HTTP/2
  implementation.");

  script_tag(name:"insight", value:"Several security issues were identified in nginx HTTP/2 implementation, which
  might cause excessive memory consumption and CPU usage (CVE-2019-9511, CVE-2019-9513, CVE-2019-9516).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx versions 1.9.5 - 1.17.2.");

  script_tag(name:"solution", value:"Update to version 1.16.1, 1.17.3 or later.");

  script_xref(name:"URL", value:"https://mailman.nginx.org/pipermail/nginx-announce/2019/000249.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.9.5", test_version2: "1.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.17", test_version2: "1.17.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.17.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
