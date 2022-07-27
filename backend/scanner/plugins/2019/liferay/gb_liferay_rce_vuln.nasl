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

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143054");
  script_version("2019-10-31T04:46:14+0000");
  script_tag(name:"last_modification", value:"2019-10-31 04:46:14 +0000 (Thu, 31 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-25 03:29:42 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-16891");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal 6.x CE RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_liferay_detect.nasl");
  script_mandatory_keys("Liferay/Installed");

  script_tag(name:"summary", value:"Liferay Portal is prone to a remote code execution vulnerability because of
  deserialization of a JSON payload.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Liferay Portal versions 6.1 GA1 (6.1.10), 6.1 GA2 (6.1.20), 6.1 GA3 (6.1.30),
  6.2 GA1 (6.2.10), 7.0 (7.0.10), 7.1 (7.1.10).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPE-16497");
  script_xref(name:"URL", value:"https://sec.vnpt.vn/2019/09/liferay-deserialization-json-deserialization-part-4/");

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

if (version_is_less_equal(version: version, test_version: "6.1.30.ga3")){
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^6\.2\." &&
    version_is_less_equal(version: version, test_version: "6.2.10.ga1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\.0\." &&
    version_is_less_equal(version: version, test_version: "7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\.1\." &&
    version_is_less_equal(version: version, test_version: "7.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
