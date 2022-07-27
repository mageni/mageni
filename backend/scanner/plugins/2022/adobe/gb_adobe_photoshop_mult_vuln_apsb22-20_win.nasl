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
  script_oid("1.3.6.1.4.1.25623.1.0.820093");
  script_version("2022-05-10T09:57:45+0000");
  script_cve_id("CVE-2022-28270", "CVE-2022-28271", "CVE-2022-28272", "CVE-2022-28273",
                "CVE-2022-28274", "CVE-2022-28275", "CVE-2022-28276", "CVE-2022-28277",
                "CVE-2022-28278", "CVE-2022-28279", "CVE-2022-24105", "CVE-2022-24098",
                "CVE-2022-23205", "CVE-2022-24099");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-04-29 12:15:42 +0530 (Fri, 29 Apr 2022)");
  script_name("Adobe Photoshop Multiple Vulnerabilities (APSB22-20) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple out-of-bounds write errors.

  - Multiple out-of-bounds read errors.

  - Multiple use after free errors.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution and information disclosure on target system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2021 prior to 22.5.7 and
  Adobe Photoshop 2022 prior to 23.3.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2021 22.5.7
  or Adobe Photoshop 2022 23.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-20.html");

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
  if(version_is_less(version:vers, test_version:"22.5.7")) {
    fix = "22.5.7";
    installed_ver = "Adobe Photoshop CC 2021";
  }
}

else if(vers =~ "^23\.")
{
  if(version_is_less(version:vers, test_version:"23.3"))
  {
    fix = "23.3";
    installed_ver = "Adobe Photoshop CC 2022";
  }
}
if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
