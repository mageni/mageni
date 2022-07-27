# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

CPE = "cpe:/a:freenas:freenas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143703");
  script_version("2020-04-15T06:09:53+0000");
  script_tag(name:"last_modification", value:"2020-04-15 06:09:53 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 05:54:37 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-11650");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeNAS 11.2 < 11.2-U8, 11.3 < 11.3-U1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_freenas_detect.nasl");
  script_mandatory_keys("freenas/detected");

  script_tag(name:"summary", value:"FreeNAS is prone to a denial of service vulnerability in the login component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The login authentication component has no limits on the length of an
  authentication message or the rate at which such messages are sent.");

  script_tag(name:"affected", value:"FreeNAS versions 11.2 and 11.3.");

  script_tag(name:"solution", value:"Update to version 11.2-U8, 11.3-U1 or later.");

  script_xref(name:"URL", value:"https://security.ixsystems.com/cves/2020-04-08-cve-2020-11650/");
  script_xref(name:"URL", value:"https://jira.ixsystems.com/browse/NAS-104748");
  script_xref(name:"URL", value:"https://github.com/weinull/CVE-2020-11650/blob/master/attack.py");

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

if (version_in_range(version: version, test_version: "11.2", test_version2: "11.2-u7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2-u8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "11.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3-u1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
