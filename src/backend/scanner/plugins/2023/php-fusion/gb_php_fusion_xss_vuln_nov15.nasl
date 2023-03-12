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
  script_oid("1.3.6.1.4.1.25623.1.0.126346");
  script_version("2023-02-20T10:17:05+0000");
  script_tag(name:"last_modification", value:"2023-02-20 10:17:05 +0000 (Mon, 20 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 13:34:35 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-06 14:57:00 +0000 (Fri, 06 Oct 2017)");

  script_cve_id("CVE-2015-8375");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 9.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHPFusion is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The robots.txt editor fails to sanitize the robots.txt file
  content as it loads the <textarea> content.");

  script_tag(name:"affected", value:"PHPFusion version prior to 9.0.");

  script_tag(name:"solution", value:"Update to version 9.0 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2015/11/29/4");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/f1a5fce791e2392d5a23a6d62ab65c481cdd6a66");

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

if (version_is_less(version: version, test_version: "9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
