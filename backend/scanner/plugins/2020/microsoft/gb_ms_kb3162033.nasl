# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815588");
  script_version("2020-04-15T15:39:23+0000");
  script_cve_id("CVE-2020-0760");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-15 15:39:23 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 09:54:48 +0530 (Wed, 15 Apr 2020)");
  script_name("Microsoft Publisher 2013 Remote Code Execution Vulnerability (KB3162033)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3162033");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists
  when Microsoft Office improperly loads arbitrary type libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Publisher 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3162033");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Publisher/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^15.*")
{
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.5233.0999"))
  {
    report = report_fixed_ver(file_checked: exePath + "\mspub.exe",
                                file_version:exeVer, vulnerable_range:"15.0 - 15.0.5233.0999");
     security_message(data:report);
     exit(0);
  }
}
exit(99);
