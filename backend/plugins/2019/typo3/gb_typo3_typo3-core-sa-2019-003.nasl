###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_typo3-core-sa-2019-003.nasl 13287 2019-01-25 09:06:21Z ckuersteiner $
#
# TYPO3 Broken Access Control Vulnerability (TYPO3-CORE-SA-2019-003)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141925");
  script_version("$Revision: 13287 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 10:06:21 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-25 15:55:22 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Broken Access Control Vulnerability (TYPO3-CORE-SA-2019-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"It has been discovered that backend users having limited access to specific
languages are capable of modifying and creating pages in the default language which actually should be disallowed.
A valid backend user account is needed in order to exploit this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TYPO3 versions 8.0.0-8.7.22.");

  script_tag(name:"solution", value:"Update to version 8.7.23 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-003/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port, version_regex: "[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.23");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
