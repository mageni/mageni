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

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147113");
  script_version("2021-11-08T14:03:29+0000");
  script_tag(name:"last_modification", value:"2021-11-08 14:03:29 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 07:20:53 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 19:10:00 +0000 (Fri, 05 Nov 2021)");

  script_cve_id("CVE-2021-43281");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB 1.2.0 < 1.8.29 RCE Vulnerability (GHSA-8gxx-vmr9-h39p)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Admin CP's Settings management module does not validate
  setting types correctly on insertion and update, making it possible to add settings of supported
  type php with PHP code, executed on on Change Settings pages. This results in an RCE
  vulnerability.

  The vulnerable module requires Admin CP access with the 'Can manage settings' permission.");

  script_tag(name:"affected", value:"MyBB version 1.2.0 through 1.8.28.");

  script_tag(name:"solution", value:"Update to version 1.8.29 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-8gxx-vmr9-h39p");

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

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.8.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
