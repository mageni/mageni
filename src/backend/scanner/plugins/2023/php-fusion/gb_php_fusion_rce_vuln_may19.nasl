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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126345");
  script_version("2023-02-20T10:17:05+0000");
  script_tag(name:"last_modification", value:"2023-02-20 10:17:05 +0000 (Mon, 20 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 10:22:35 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-12099");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 9.03.00 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHPFusion is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Allows remote authenticated users to execute arbitrary code
  because includes/dynamics/includes/form_fileinput.php and
  includes/classes/PHPFusion/Installer/Lib/Core.settings.inc mishandle executable files during
  avatar upload.");

  script_tag(name:"affected", value:"PHPFusion version prior to 9.03.00.");

  script_tag(name:"solution", value:"Update to version 9.03.00 or later.");

  script_xref(name:"URL", value:"https://www.pentest.com.tr/exploits/PHP-Fusion-9-03-00-Edit-Profile-Remote-Code-Execution.html");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/943432028b9e674433bb3f2a128b2477134110e6");

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

if (version_is_less(version: version, test_version: "9.03.00")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.03.00", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
