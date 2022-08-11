# Copyright (C) 2022 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819906");
  script_version("2022-01-06T05:11:00+0000");
  script_cve_id("CVE-2021-43018", "CVE-2021-43020", "CVE-2021-44184");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-06 10:37:42 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-03 08:25:27 +0530 (Mon, 03 Jan 2022)");
  script_name("Adobe Photoshop Multiple Vulnerabilities (APSB21-113) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Out-of-bounds Write error.

  - Buffer Overflow error.

  - Access of Memory Location After End of Buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code or disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2021 prior to 22.5.4 and
  Adobe Photoshop 2022 prior to 23.1.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2021 22.5.4
  or Adobe Photoshop 2022 23.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-113.html");

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^22\.")
{
  if(version_is_less(version:vers, test_version:"22.5.4")) {
    fix = "22.5.4";
    installed_ver = "Adobe Photoshop CC 2021";
  }
}

else if(vers =~ "^23\.")
{
  if(version_is_less(version:vers, test_version:"23.1"))
  {
    fix = "23.1";
    installed_ver = "Adobe Photoshop CC 2022";
  }
}
if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
