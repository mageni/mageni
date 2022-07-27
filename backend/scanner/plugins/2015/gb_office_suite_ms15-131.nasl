###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Suite Remote Code Execution Vulnerabilities (3116111)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806174");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6118", "CVE-2015-6124", "CVE-2015-6172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-09 12:09:07 +0530 (Wed, 09 Dec 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3116111)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-131.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist in the way that Microsoft
  Outlook parses specially crafted email messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 2 and prior

  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085549");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114403");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114425");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-131");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007
if(officeVer && officeVer =~ "^12\.")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(dllPath)
  {
    msoVer  =  fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\OFFICE12\mso.dll");
    if(msoVer)
    {
      if(version_in_range(version:msoVer, test_version:"12.0", test_version2:"12.0.6739.4999"))
      {
        report = 'File checked:     ' + dllPath + "\Microsoft Shared\OFFICE12" + "\mso.dll" + '\n' +
                 'File version:     ' + msoVer + '\n' +
                 'Vulnerable range: 12.0 - 12.0.6739.4999 \n' ;
        security_message(data:report);
        exit(0);
      }
    }

    mspVer  =  fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\OFFICE12\msptls.dll");
    if(mspVer)
    {
      if(version_in_range(version:mspVer, test_version:"12.0", test_version2:"12.0.6739.4999"))
      {
        report = 'File checked:     ' + dllPath + "\Microsoft Shared\OFFICE12" + "\msptls.dll" + '\n' +
                 'File version:     ' + mspVer + '\n' +
                 'Vulnerable range: 12.0 - 12.0.6739.4999 \n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
## version check for office 2010 https://support.microsoft.com/en-us/kb/2965311
## MS Office 2010
if(officeVer && officeVer =~ "^14\.")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");

  if(dllPath)
  {
    dllVer  = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\OFFICE14\msptls.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7164.4999"))
      {
        report = 'File checked:     ' + dllPath + "\Microsoft Shared\OFFICE14" + "\msptls.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                'Vulnerable range: 14.0 - 14.0.7164.4999 \n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
