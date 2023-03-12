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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826925");
  script_version("2023-02-21T10:09:30+0000");
  script_cve_id("CVE-2023-21593");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 12:12:21 +0530 (Thu, 16 Feb 2023)");
  script_name("Adobe InDesign Denial of Service Vulnerability (APSB23-12) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe InDesign February 2023 update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a NULL Pointer Dereference
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service on the system.");

  script_tag(name:"affected", value:"Adobe InDesign 18.1 and earlier versions,
  17.4 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 18.2 or
  17.4.1 or later.Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb23-12.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.4")) {
  fix = "17.4.1";
}

if (version_in_range(version: vers, test_version: "18.0", test_version2: "18.1")) {
  fix = "18.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(data: report);
  exit(0);
}

exit(99);
