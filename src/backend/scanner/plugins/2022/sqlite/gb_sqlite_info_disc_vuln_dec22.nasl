# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126250");
  script_version("2022-12-14T10:20:42+0000");
  script_tag(name:"last_modification", value:"2022-12-14 10:20:42 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-13 12:28:38 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2022-46908");

  script_name("SQLite <= 3.40.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When relying on --safe flag, execution of an untrusted CLI script,
  does not properly implement the azProhibitedFunctions protection mechanism, and instead allows
  UDF functions such as WRITEFILE.");

  script_tag(name:"affected", value:"SQLite version 3.40.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 13th December, 2022.
  Information regarding this issue will be updated once solution details are available.

  Note: Fix will probably be released in new version, since it's already fixed on trunk.");

  script_xref(name:"URL", value:"https://sqlite.org/src/info/cefc032473ac5ad2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.40.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
