###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (KB4040972 and KB4040971)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811828");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8759");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-14 11:19:26 +0530 (Thu, 14 Sep 2017)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (KB4040972 and KB4040971)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates KB4040972 and KB4040971.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to Microsoft .NET Framework
  processes untrusted input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take control of an affected system. An attacker could then install
  programs, view, change, or delete data, or create new accounts with full user
  rights. Users whose accounts are configured to have fewer user rights on the
  system could be less impacted than users who operate with administrative user
  rights.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.6

  Microsoft .NET Framework 4.6.1

  Microsoft .NET Framework 4.6.2

  Microsoft .NET Framework 4.7");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040972");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040971");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040972");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  dotPath = registry_get_sz(key:key + item, item:"Path");
  if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
  {
    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"system.dll");
    if(!sysdllVer){
      exit(0);
    }

    ## .NET Framework 4.6/4.6.1/4.6.2/4.7 for Windows 8.1, Windows Server 2012 R2 and Windows Server 2012
    if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.7.2113"))
    {
      report = 'File checked:     ' + dotPath + "\system.dll" + '\n' +
               'File version:     ' + sysdllVer  + '\n' +
               'Vulnerable range: 4.6 - 4.7.2113\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
