###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Suite Multiple Vulnerabilities (3199168)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809718");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-7232", "CVE-2016-7244", "CVE-2016-7245", "CVE-2016-7233",
                "CVE-2016-7234", "CVE-2016-7235");
  script_bugtraq_id(94005, 94022, 94026, 94020, 94031, 94029);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-09 11:41:38 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Multiple Vulnerabilities (3199168)");

  script_tag(name:"summary", value:"This host is missing an important
  update according to Microsoft Bulletin MS16-133.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Office software fails to properly handle objects in memory.

  - Office or Word reads out of bound memory due to an uninitialized variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user, gain access
  to potentially sensitive information and cause Office to stop responding.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3
  Microsoft Office 2010 Service Pack 2
  Microsoft Office 2013 Service Pack 1
  Microsoft Office 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3127951");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118396");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2986253");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115120");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115153");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115135");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-133");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

##https://support.microsoft.com/en-us/kb/3127951
##File information not available

#https://support.microsoft.com/en-us/kb/3118396
if(offVer =~ "^12\..*")
{
  offPath = path + "\Microsoft Shared\Office12" ;

  offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
  if(offexeVer)
  {
    if(version_in_range(version:offexeVer, test_version:"12.0", test_version2:"12.0.6759.4999"))
    {
      report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
               'File version:     ' + offexeVer  + '\n' +
               'Vulnerable range: ' + "12.0 - 12.0.6759.4999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

## https://support.microsoft.com/en-us/kb/2986253
## MS Office 2007
if(offVer =~ "^12.*")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                item:"CommonFilesDir");
  if(dllPath)
  {
    dllVer6 = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\VBA\VBA6\VBE6.DLL");
    if(dllVer6)
    {
      if(version_is_less(version:dllVer6, test_version:"6.5.10.57"))
      {
        report = 'File checked:     ' + dllPath + "Microsoft Shared\VBA\VBA6\VBE6.DLL" + '\n' +
                 'File version:     ' + dllVer6  + '\n' +
                 'Vulnerable range: ' + "Less than 6.5.10.57" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

##https://support.microsoft.com/en-us/kb/3115120
## MS Office 2010
if(offVer =~ "^14.*")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                item:"CommonFilesDir");
  if(dllPath)
  {
    vbVer = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\VBA\VBA7\VBE7.DLL");
    if(vbVer)
    {
      if(version_is_less(version:vbVer, test_version:"7.0.16.40"))
      {
        report = 'File checked:     ' + dllPath + "Microsoft Shared\VBA\VBA7\VBE7.DLL" + '\n' +
                 'File version:     ' + vbVer  + '\n' +
                 'Vulnerable range: ' + "Less than 7.0.16.40" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

##https://support.microsoft.com/en-us/kb/3115153
## MS Office 2013
if(offVer =~ "^15.*")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                item:"CommonFilesDir");

  if(dllPath)
  {
    vbVer = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\VBA\VBA7.1\VBEUI.DLL");
    if(vbVer)
    {
      if(version_is_less(version:vbVer, test_version:"7.1.15.4663"))
      {
        report = 'File checked:     ' + dllPath + "\Microsoft Shared\VBA\VBA7.1\VBEUI.DLL" + '\n' +
                 'File version:     ' + vbVer  + '\n' +
                 'Vulnerable range: ' + "Less than 7.1.15.4663" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

##https://support.microsoft.com/en-us/kb/3115135
## MS Office 2016
if(offVer =~ "^16.*")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                item:"CommonFilesDir");

  if(dllPath)
  {
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
    if(path)
    {
      ##For x86 based installation
      ##To Do, Check path for 64bit installation and update path here
      vbPath = path + "\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\VBA\VBA7.1\";
      vbVer = fetch_file_version(sysPath:vbPath, file_name:"VBE7.DLL");
      if(vbVer)
      {
        if(version_is_less(version:vbVer, test_version:"7.1.10.56"))
        {
          report = 'File checked:     ' + vbPath + "VBE7.DLL" + '\n' +
                   'File version:     ' + vbVer  + '\n' +
                   'Vulnerable range: ' + "Less than 7.1.10.56" + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
