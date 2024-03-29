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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826700");
  script_version("2022-11-10T15:31:00+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-10 15:31:00 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-09 10:02:34 +0530 (Wed, 09 Nov 2022)");
  script_name("Microsoft Office Defense in Depth Update (ADV220003)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3191875/KB3191869.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Microsoft has released an update for
  Microsoft Office that provides enhanced security as a defense in depth measure.
  This update provides hardening around IRM-protected documents to ensure the
  trust-of-certificate chain.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to compromise system's confidentiality.");

  script_tag(name:"affected", value:"- Microsoft Word 2013 Service Pack 1

  - Microsoft Office 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191875");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191869");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer || officeVer !~ "^1[56]\."){
  exit(0);
}

if(!os_arch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  msPath = registry_get_sz(key:key, item:"ProgramFilesDir");
  if(msPath)
  {
    if(officeVer =~ "^15\."){
      offPath = msPath + "\Microsoft Office\Office15\MSIPC";
    }
    else{
      offPath = msPath + "\Microsoft Office\root\Office16\MSIPC";
    }

    msdllVer = fetch_file_version(sysPath:offPath, file_name:"msipc.dll");

    if(version_is_less(version:msdllVer, test_version:"1.0.5017.0"))
    {
      report = report_fixed_ver( file_checked:offPath + "\msipc.dll",
                                 file_version:msdllVer, vulnerable_range:"Less than 1.0.5017.0");
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
