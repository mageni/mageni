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

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821399");
  script_version("2023-03-16T10:09:04+0000");
  script_cve_id("CVE-2023-26358");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-16 10:09:04 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-15 14:58:19 +0530 (Wed, 15 Mar 2023)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Creative Cloud Desktop Application RCE Vulnerability APSB23-21 (Windows)");

  script_tag(name:"summary", value:"Adobe Creative Cloud is prone to a high-risk vulnerability that can lead to remote code execution");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the application
  loads DLL libraries in an insecure manner.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code and escalate privileges on the
  target system.");

  script_tag(name:"affected", value:"Adobe Creative Cloud Desktop Application 5.9.1
  and earlier version on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud Desktop Application version
  5.10 Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb23-11.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/creative-cloud");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos['version'];
cloudPath = infos['location'];

if(version_is_less(version:cloudVer, test_version:"5.10"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"5.10", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
