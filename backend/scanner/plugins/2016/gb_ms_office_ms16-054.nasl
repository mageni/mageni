###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Multiple Remote Code Execution Vulnerabilities (3155544)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807820");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0126", "CVE-2016-0140", "CVE-2016-0183", "CVE-2016-0198");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-05-11 11:36:04 +0530 (Wed, 11 May 2016)");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (3155544)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-054.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to,

  - Multiple memory corruption errors.

  - An error as windows font library improperly handles specially crafted embedded
  fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3

  Microsoft Office 2010 Service Pack 2

  Microsoft Office 2013 Service Pack 1

  Microsoft Office 2016 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101520");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2984943");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2984938");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2984938");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3054984");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115016");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115121");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3155544");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-054");
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

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

## MS Office 2007,2010
if(officeVer =~ "^1[24]\.")
{
  foreach offpath (make_list("12.0", "14.0"))
  {
    comPath = registry_get_sz(key:"SOFTWARE\Microsoft\Office\" + offpath  + "\Access\InstallRoot",
                           item:"Path");
    if(comPath)
    {
      ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
      ortconVer = fetch_file_version(sysPath:comPath, file_name:"Oartconv.dll");

      if(ortVer)
      {
        ## https://support.microsoft.com/en-us/kb/2984943
        ##2007 Microsoft Office Suite
        if(version_in_range(version:ortVer, test_version:"12.0", test_version2:"12.0.6748.4999"))
        {
          Vulnerable_range1  =  "12.0 - 12.0.6748.4999";
          VULN1 = TRUE ;
        }

        ## https://support.microsoft.com/en-us/kb/3101520
        ## Office 2010
        else if(version_in_range(version:ortVer, test_version:"14.0", test_version2:"14.0.7169.4999"))
        {
          Vulnerable_range1  =  "14.0 - 14.0.7169.4999";
          VULN1 = TRUE ;
        }
      }

      if(ortconVer)
      {
        ## 2007 Microsoft Office Suite
        ## https://support.microsoft.com/en-us/kb/2984938
        if(version_in_range(version:ortconVer, test_version:"12.0", test_version2:"12.0.6748.4999"))
        {
          Vulnerable_range2  =  "12.0 - 12.0.6748.4999";
          VULN2 = TRUE ;
        }

        ##Office 2010
        ## https://support.microsoft.com/en-us/kb/3054984
        else if(version_in_range(version:ortconVer, test_version:"14.0", test_version2:"14.0.7169.4999"))
        {
          Vulnerable_range2  =  "14.0 - 14.0.7169.4999";
          VULN2 = TRUE ;
        }
      }
    }
  }
}

## https://support.microsoft.com/en-us/kb/3115121
## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring

##Office 2013
if(officeVer =~ "^15\.")
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"CommonFilesDir");
  if(InsPath)
  {
    offsubver = "Office15";
    offPath = InsPath + "\Microsoft Shared\" + offsubver;
    exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

    if(exeVer)
    {
      ## https://support.microsoft.com/en-us/kb/3115016
      ## Office 2013
      if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4823.999"))
      {
          Vulnerable_range3  =  "15.0 - 15.0.4823.999";
          VULN3 = TRUE ;
      }
    }
  }
}

##Office 2016
if(officeVer =~ "^16\.")
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"CommonFilesDir");
  if(InsPath)
  {
    offsubver = "Office16";
    offPath = InsPath + "\Microsoft Shared\" + offsubver;

    exeVer = fetch_file_version(sysPath:offPath, file_name:"mso40uires.dll");
    if(exeVer)
    {
      ## https://support.microsoft.com/en-us/kb/3115016
      ## Office 2013
      if(version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4297.999"))
      {
          Vulnerable_range4  =  "16.0 - 16.0.4297.999";
          VULN4 = TRUE ;
      }
    }
  }
}

if(VULN1)
{
  report = 'File checked:     ' + comPath + "\Oart.dll" + '\n' +
           'File version:     ' + ortVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
}

else if(VULN2)
{
  report = 'File checked:     ' + comPath + "\Oartconv.dll" + '\n' +
           'File version:     ' + ortconVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
}

else if(VULN3)
{
  report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
  security_message(data:report);
}

else if(VULN4)
{
  report = 'File checked:     ' + offPath + "\mso40uires.dll" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range4 + '\n' ;
  security_message(data:report);
}

exit(0);
