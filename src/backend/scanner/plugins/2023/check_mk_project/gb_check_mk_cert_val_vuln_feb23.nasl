# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149405");
  script_version("2023-03-06T10:10:03+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:03 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-06 04:26:21 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2022-23491");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check MK 1.6.x < 2.2.0b1, 2.3.x < 2.3.0b1 Certification Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Check MK is prone to a certification validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The compiled version of the agent-updater uses its own
  collection of trusted Certificate Authorities. This collection comes from the Python package
  certifi and is based on the collection of Mozilla Firefox. The used Python package and therefore
  the collection was outdated and is subject to CVE-2022-23491. This collection included a CA
  certificate of TrustCor which is not considered trustworthy anymore.");

  script_tag(name:"impact", value:"If an attacker is able to create certificates for arbitrary
  domains signed by this CA, machine-in-the-middle attacks could be possible.");

  script_tag(name:"affected", value:"Check MK version 1.6.x prior to 2.2.0b1 and 2.3.x prior to
  2.3.0b1.");

  script_tag(name:"solution", value:"Update to version 2.2.0b1, 2.3.0b1 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/15068");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.6.0", test_version_up: "2.2.0b1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.0b1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.3.0", test_version_up: "2.3.0b1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.0b1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
