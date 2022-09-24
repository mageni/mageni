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
  script_oid("1.3.6.1.4.1.25623.1.0.826524");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2022-24090");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-21 15:37:00 +0000 (Mon, 21 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-09-15 15:33:39 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Photoshop Information Disclosure Vulnerability (APSB22-14) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw is due to an access of memory
  location after end of Buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  leak memory on the target system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2021 prior to 22.5.6 and
  Adobe Photoshop 2022 prior to 23.2.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2021 22.5.6
  or Adobe Photoshop 2022 23.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-14.html");

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
  if(version_is_less(version:vers, test_version:"22.5.6")) {
    fix = "22.5.6";
    installed_ver = "Adobe Photoshop 2021";
  }
}

else if(vers =~ "^23\.")
{
  if(version_is_less(version:vers, test_version:"23.2")) {
    fix = "23.2";
    installed_ver = "Adobe Photoshop 2022";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
