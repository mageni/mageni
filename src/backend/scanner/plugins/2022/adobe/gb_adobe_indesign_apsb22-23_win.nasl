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

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821115");
  script_version("2022-05-19T11:50:09+0000");
  script_cve_id("CVE-2022-28831", "CVE-2022-28832", "CVE-2022-28833");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-20 09:52:18 +0000 (Fri, 20 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-12 17:38:45 +0530 (Thu, 12 May 2022)");
  script_name("Adobe InDesign RCE Vulnerabilities (APSB22-23) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe May update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaws exist due to an out-of-bounds read error and out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Adobe InDesign 17.1 and earlier versions, 16.4.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 17.2 or
  later, 16.4.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb22-23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "17.2", install_path: path);
  security_message(data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "16.0.0", test_version2: "16.4.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "16.4.2", install_path: path);
  security_message(data: report);
  exit(0);
}

exit(99);
