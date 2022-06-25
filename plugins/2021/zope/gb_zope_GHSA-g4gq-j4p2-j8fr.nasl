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

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146437");
  script_version("2021-08-04T09:33:21+0000");
  script_tag(name:"last_modification", value:"2021-08-05 10:56:26 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-04 09:22:51 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-32811");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope RCE Vulnerability (GHSA-g4gq-j4p2-j8fr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zope_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a remote code execution (RCE) vulnerability
  via Script (Python) objects under Python 3.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The optional add-on package Products.PythonScripts adds Script
  (Python) to the list of content items a user can add to the Zope object database. Inside these
  scripts users can write Python code that is executed when rendered through the web. The code
  environment in these script objects is limited, it relies on the RestrictedPython package to
  provide a 'safe' subset of Python instructions as well as the AccessControl package that defines
  security policies for execution in the context of a Zope application.

  Recently the AccessControl package was updated to fix a remote code execution security issue. The
  bug tightens the AccessControl security policies for Zope by blocking access to unsafe classes
  inside the Python string module.

  You are only affected if the following are true:

  - You use Python 3 for your Zope deployment (Zope 4 on Python 2 is not affected)

  - You run Zope 4 below version 4.6.3 or Zope 5 below version 5.3

  - You have installed the optional Products.PythonScripts add-on package

  By default, you need to have the admin-level Zope 'Manager' role to add or edit Script (Python)
  objects through the web. Only sites that allow untrusted users to add/edit these scripts through
  the web are at risk.");

  script_tag(name:"affected", value:"Zope version 4.0 through 4.6.2 and 5.0 through 5.2.");

  script_tag(name:"solution", value:"Update to version 4.6.3, 5.3 or later.");

  script_xref(name:"URL", value:"https://github.com/zopefoundation/Zope/security/advisories/GHSA-g4gq-j4p2-j8fr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\." && version_is_less(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
