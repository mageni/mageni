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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142495");
  script_version("2019-06-05T09:38:24+0000");
  script_tag(name:"last_modification", value:"2019-06-05 09:38:24 +0000 (Wed, 05 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-05 09:11:05 +0000 (Wed, 05 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5211", "CVE-2017-5212");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) AppSuite Multiple Vulnerabilities (Jan17)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");

  script_tag(name:"summary", value:"Open-Xchange (OX) AppSuite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Open-Xchange (OX) AppSuite is prone to multiple vulnerabilities:

  - Content Spoofing (CVE-2017-5211)

  - Incorrect Access Control (CVE-2017-5212)");

  script_tag(name:"solution", value:"Update to version 7.8.3-rev11, 7.8.4-rev3 or later.");

  script_xref(name:"URL", value:"https://documentation.open-xchange.com/7.8.3/release-notes/release-notes.html");
  script_xref(name:"URL", value:"https://documentation.open-xchange.com/7.8.4/release-notes/release-notes.html");

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

if (!revision = get_kb_item("open_xchange_appsuite/" + port + "/revision"))
  exit(0);

version += '.' + revision;

if (version_is_less(version: version, test_version: "7.8.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.3.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.4", test_version2: "7.8.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
