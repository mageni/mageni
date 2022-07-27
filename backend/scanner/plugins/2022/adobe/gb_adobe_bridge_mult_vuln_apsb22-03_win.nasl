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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819929");
  script_version("2022-01-14T07:06:50+0000");
  script_cve_id("CVE-2021-44743", "CVE-2021-45051", "CVE-2021-45052", "CVE-2021-44187",
                "CVE-2021-44186", "CVE-2021-44185");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-14 11:23:55 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 11:07:26 +0530 (Thu, 13 Jan 2022)");
  script_name("Adobe Bridge Security Update (APSB22-03) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe January update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - An out-of-bounds write error.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, escalate privileges and disclose information
  on the affected system.");

  script_tag(name:"affected", value:"Adobe Bridge 11.1.2 and earlier versions,
  12.x prior to 12.0.1 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Bridge to version 11.1.3 or 12.0.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb22-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"11.1.3")){
  fix = "11.1.3";
} else if(vers =~ "^12\." && version_is_less(version:vers, test_version:"12.0.1")){
    fix = "12.0.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
