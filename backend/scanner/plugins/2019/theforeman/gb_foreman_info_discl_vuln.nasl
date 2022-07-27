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

CPE = "cpe:/a:theforeman:foreman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142373");
  script_version("2019-05-11T15:07:16+0000");
  script_tag(name:"last_modification", value:"2019-05-11 15:07:16 +0000 (Sat, 11 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-06 12:22:46 +0000 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2019-3893");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman < 1.20.3 and 1.21.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_detect.nasl");
  script_mandatory_keys("foreman/installed");

  script_tag(name:"summary", value:"Foreman is prone to an authenticated information dislosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the delete compute resource operation, when executed
  from the Foreman API, leads to the disclosure of the plaintext password or token for the affected compute
  resource.");

  script_tag(name:"impact", value:"A malicious user with the 'delete_compute_resource' permission can use this
  flaw to take control over compute resources managed by foreman.");

  script_tag(name:"affected", value:"Foreman version prior to 1.20.3 and 1.21.1.");

  script_tag(name:"solution", value:"Update to version 1.20.3, 1.21.1 or later.");

  script_xref(name:"URL", value:"https://projects.theforeman.org/issues/26450");

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

if (version_is_less(version: version, test_version: "1.20.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.20.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.21.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.21.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
