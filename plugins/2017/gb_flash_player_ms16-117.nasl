###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IE And Microsoft Edge Flash Player Multiple Vulnerabilities (3188128)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_player_internet_explorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810642");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-4271", "CVE-2016-4272", "CVE-2016-4274", "CVE-2016-4275",
                "CVE-2016-4276", "CVE-2016-4277", "CVE-2016-4278", "CVE-2016-4279",
                "CVE-2016-4280", "CVE-2016-4281", "CVE-2016-4282", "CVE-2016-4283",
                "CVE-2016-4284", "CVE-2016-4285", "CVE-2016-4287", "CVE-2016-6921",
                "CVE-2016-6922", "CVE-2016-6923", "CVE-2016-6924", "CVE-2016-6925",
                "CVE-2016-6926", "CVE-2016-6927", "CVE-2016-6929", "CVE-2016-6930",
                "CVE-2016-6931", "CVE-2016-6932", "CVE-2016-4182", "CVE-2016-4237",
                "CVE-2016-4238");
  script_bugtraq_id(92923, 91725, 92930, 92927, 92924);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-17 19:54:05 +0530 (Fri, 17 Mar 2017)");
  script_name("Microsoft IE And Microsoft Edge Flash Player Multiple Vulnerabilities (3188128)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-117");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An integer overflow vulnerability.

  - The use-after-free vulnerabilities.

  - The security bypass vulnerabilities.

  - Multiple memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers lead to code execution and
  information disclosure.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 x32/x64

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-117");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-29.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms16-117");
  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:adobe:flash_player_edge";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
    exit(0);
  }
}

flashVer = infos['version'];
if(!flashVer){
  exit(0);
}

flashPath = infos['location'];
if(flashPath){
  flashPath = flashPath + "\Flashplayerapp.exe";
} else {
  flashPath = "Could not find the install location";
}

if(version_is_less(version:flashVer, test_version:"23.0.0.162"))
{
  report = 'File checked:     ' + flashPath + '\n' +
           'File version:     ' + flashVer  + '\n' +
           'Vulnerable range: ' + "Less than 23.0.0.162" + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(99);