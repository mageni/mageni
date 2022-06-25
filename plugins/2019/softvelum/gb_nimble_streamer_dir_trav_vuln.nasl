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

CPE = 'cpe:/a:softvelum:nimble_streamer';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142789");
  script_version("2019-08-26T07:31:18+0000");
  script_tag(name:"last_modification", value:"2019-08-26 07:31:18 +0000 (Mon, 26 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-26 07:05:52 +0000 (Mon, 26 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2019-11013");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nimble Streamer 3.0.2-2 <= 3.5.4-9 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nimble_streamer_detect.nasl");
  script_mandatory_keys("nimble_streamer/detected");

  script_tag(name:"summary", value:"Nimble Streamer is prone to a directory traversal vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to traverse the file system to
  access files or directories that are outside of the restricted directory on the remote server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nimble Streamer versions 3.0.2-2 to 3.5.4-9.");

  script_tag(name:"solution", value:"Update to the latest version available.");

  script_xref(name:"URL", value:"https://mayaseven.com/nimble-directory-traversal-in-nimble-streamer-version-3-0-2-2-to-3-5-4-9/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47301");

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

if (version_in_range(version: version, test_version: "3.0.2-2", test_version2: "3.5.4-9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.5-1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
