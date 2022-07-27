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

CPE = 'cpe:/a:freepbx:freepbx';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142584");
  script_version("2019-07-11T08:20:10+0000");
  script_tag(name:"last_modification", value:"2019-07-11 08:20:10 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 08:05:36 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-15891");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX < 13.0.122.43, < 14.0.18.34 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_detect.nasl");
  script_mandatory_keys("freepbx/installed");

  script_tag(name:"summary", value:"FreePBX is prone to a stored cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By crafting a request for adding Asterisk modules, an attacker is able to
  store JavaScript commands in a module name.");

  script_tag(name:"affected", value:"FreePBX prior to version 13.0.122.43 and prior to version 14.0.18.34.");

  script_tag(name:"solution", value:"Update to version 13.0.122.43, 14.0.18.34 or later.");

  script_xref(name:"URL", value:"https://wiki.freepbx.org/display/FOP/2018-09-11+Core+Stored+XSS");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_less(version: version, test_version: "13.0.122.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.122.43", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14", test_version2: "14.0.18.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.18.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
