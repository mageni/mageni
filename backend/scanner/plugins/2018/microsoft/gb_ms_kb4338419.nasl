###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Multiple Vulnerabilities (KB4338419)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813490");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8356", "CVE-2018-8284", "CVE-2018-8202", "CVE-2018-8260");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-11 12:06:24 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB4338419)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4338419.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when Microsoft .NET Framework components do not correctly validate
    certificates.

  - An error in the way how .NET Framework activates COM objects.

  - An error when the Microsoft .NET Framework fails to validate input properly.

  - An error when the .NET software when the software fails to check the source
    markup of a file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges, bypass security restrictions and take control of an
  affected system allowing to install programs or view data, change data, delete
  data or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.6, 4.6.1, 4.6.2,
  4.7, 4.7.1 for Windows 8.1 and Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4338419/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

key2 = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\";
if(!registry_key_exists(key:key2)){
  exit(0);
}

foreach item (registry_enum_keys(key:key2))
{
  path = registry_get_sz(key:key2 + item, item:"All Assemblies In");
  if(path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"system.identitymodel.dll");
    if(dllVer)
    {
      if(dllVer =~ "^(4\.(6|7))" && version_is_less(version:dllVer, test_version:"4.7.3130.0"))
      {
        report = report_fixed_ver(file_checked:path + "system.identitymodel.dll",
                                  file_version:dllVer, vulnerable_range:"4.6 - 4.7.3129");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(0);
