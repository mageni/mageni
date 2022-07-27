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

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140206");
  script_version("2019-06-11T03:47:50+0000");
  script_tag(name:"last_modification", value:"2019-06-11 03:47:50 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 02:44:42 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-6588");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal < 7.0 CE GA4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_liferay_detect.nasl");
  script_mandatory_keys("Liferay/Installed");

  script_tag(name:"summary", value:"Liferay Portal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Liferay Portal is prone to multiple vulnerabilities:

  - Velocity/FreeMarker templates do not properly restrict variable usage

  - Multiple permission vulnerabilities in 7.0 CE GA3

  - Multiple XSS vulnerabilities in 7.0 CE GA3

  - Password policy circumvention via forgot password

  - DoS vulnerability via SessionClicks

  - RCE via TunnelServlet

  - ThreadLocal may leak variables

  - Password exposure in Server Administration

  - Password exposure during a data migration

  - Open redirect vulnerability in Search

  - DoS vulnerabilities in Apache Commons FileUpload

  - XXE vulnerability in Apache Tika");

  script_tag(name:"affected", value:"Liferay Portal prior to version 7.0.2 CE GA3.");

  script_tag(name:"solution", value:"Update to version 7.0.2 CE GA3 or later.");

  script_xref(name:"URL", value:"https://portal.liferay.dev/learn/security/known-vulnerabilities/-/categories/113764476?p_r_p_categoryId=113764476");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "7.0.2.GA3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.2.GA3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
