# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814951");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-0824", "CVE-2019-0826", "CVE-2019-0827");
  script_bugtraq_id(107744, 107746, 107747);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-10 10:54:00 +0530 (Wed, 10 Apr 2019)");
  script_name("Microsoft Office 2013 Service Pack 1 Multiple Vulnerabilities (KB4462204)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4462204");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist when the Microsoft
  Office Access Connectivity Engine improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  elevate privileges and execute arbitrary code in the context of the currently
  logged-in user. Failed exploit attempts will likely result in denial of service
  conditions.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4462204");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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
  msPath = registry_get_sz(key:key, item:"CommonFilesDir");
  if(msPath)
  {
    offPath = msPath + "\Microsoft Shared\Office15";
    msdllVer = fetch_file_version(sysPath:offPath, file_name:"acecore.dll");

    if(msdllVer && msdllVer =~ "15\.")
    {
      if(version_is_less(version:msdllVer, test_version:"15.0.5125.1000"))
      {
        report = report_fixed_ver( file_checked:offPath + "\acecore.dll",
                                   file_version:msdllVer, vulnerable_range:"15.0 - 15.0.5125.0999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(99);
