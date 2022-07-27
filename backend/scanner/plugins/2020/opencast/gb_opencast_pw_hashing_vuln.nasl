# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143445");
  script_version("2020-02-04T08:04:36+0000");
  script_tag(name:"last_modification", value:"2020-02-04 08:04:36 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 07:27:24 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2020-5229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 8.1.0 Password Hashing Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to an insecure password hashing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"User passwords are stored in the database using the rather outdated and
  cryptographically insecure MD5 hash algorithm. Furthermore, the hashes are salted using the username instead of
  a random salt, causing hashes for users with the same username and password to collide which is problematic
  especially for popular users like the default admin user.

  This essentially means that for an attacker, it might be feasible to reconstruct a user's password given access
  to these hashes.

  Note that attackers needing access to the hashes means that they must gain access to the database in which these
  are stored first to be able to start cracking the passwords.");

  script_tag(name:"affected", value:"OpenCast versions prior to 8.1.0.");

  script_tag(name:"solution", value:"Update to version 8.1.0 or later. Note, that old hashes remain MD5 until the
  password is updated.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-h362-m8f2-5x7c");

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

if (version_is_less(version: version, test_version: "8.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
