# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source
# are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112603");
  script_version("2019-07-11T12:15:26+0000");
  script_tag(name:"last_modification", value:"2019-07-11 12:15:26 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 13:53:11 +0200 (Thu, 11 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 9.3.x <= 9.5.7 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 CMS is susceptible to a broken access control vulnerability.");

  script_tag(name:"insight", value:"It has been discovered that the Import/Export module is susceptible to broken access control.
  Regular backend users have access to import functionality which usually only is available to admin users or users having
  User TSconfig setting options.impexp.enableImportForNonAdminUser explicitly enabled.

  A valid backend user account is needed in order to exploit this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TYPO3 versions 9.3.0 through 9.5.7.");

  script_tag(name:"solution", value:"Update to version 9.5.8 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-017/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if(version_in_range(version: version, test_version: "9.3.0", test_version2: "9.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
