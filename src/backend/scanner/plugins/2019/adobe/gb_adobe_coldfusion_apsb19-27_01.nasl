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

CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112084");
  script_version("2019-06-12T10:35:21+0000");
  script_tag(name:"last_modification", value:"2019-06-12 10:35:21 +0000 (Wed, 12 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-12 12:22:43 +0200 (Wed, 12 Jun 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-7838", "CVE-2019-7840");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB19-27)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilites exist:

  - File extension blacklist bypass (CVE-2019-7838)

  - Deserialization of untrusted data (CVE-2019-7840)");

  script_tag(name:"impact", value:"Successful exploitation could lead to arbitrary code execution.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 11 prior to Update 19, version 2016 prior to Update 11 and version 2018 prior to Update 4.");

  script_tag(name:"solution", value:"Update to version 11 Update 19, version 2016 Update 11 or version 2018 Update 4 respectively.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-27.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/in/coldfusion/kb/coldfusion-11-update-19.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-11.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-update-4.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if(version =~ "^11\.0" && version_is_less(version: version, test_version: "11.0.19.314545")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.19.314546", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version =~ "^2016\.0" && version_is_less(version: version, test_version: "2016.0.11.314545")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2016.0.11.314546", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version =~ "^2018\.0" && version_is_less(version: version, test_version: "2018.0.04.314545")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018.0.04.314546", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
