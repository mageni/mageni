###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-035.nasl 0057419 2016-03-10 09:15:08Z mar$
#
# Microsoft .NET XML Validation Security Feature Bypass Vulnerability (3141780)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807311");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2016-0132");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-03-09 12:03:21 +0530 (Wed, 09 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft .NET XML Validation Security Feature Bypass Vulnerability (3141780)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-035");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of objects
  in memory by .NET's Windows Forms (WinForms) libraries and error when decrypting
  specially crafted XML data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges or disrupt the availability of
  applications that use the .NET framework.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.0

  Microsoft .NET Framework 4.5.2

  Microsoft .NET Framework 4.6 and 4.6.1

  Microsoft .NET Framework 3.5 and 3.5.1

  Microsoft .NET Framework 2.0 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3141780");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-035");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3,
   win2008r2:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    dllVer2 = fetch_file_version(sysPath:path, file_name:"System.Security.dll");
    if(dllVer2)
    {

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
         if(version_in_range(version:dllVer2, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4261"))
         {
           VULN = TRUE ;
           vulnerable_range = "2.0.50727.4000 - 2.0.50727.4261 ";
         }

         if(version_in_range(version:dllVer2, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8682"))
         {
           VULN = TRUE ;
           vulnerable_range = "2.0.50727.8000 - 2.0.50727.8682";
         }
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      else if(hotfix_check_sp(win2012:1) > 0)
      {
        if(version_in_range(version:dllVer2, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6431"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.6000 - 2.0.50727.6431";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8684"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.8000 - 2.0.50727.8684";
        }
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
      {
        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8684"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.8600 - 2.0.50727.8684";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8019"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.8000 - 2.0.50727.8019";
        }
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer2, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5495"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.5400 - 2.0.50727.5495";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8683"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.8000 - 2.0.50727.8683";
        }
      }

      ##  NET Framework 4.5.2 in Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer2, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34290"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.0.30319.34000 - 4.0.30319.34290";
        }
      }

      # .NET Framework 4.5.2 on Windows Server 2012
      else if((hotfix_check_sp(win2012:1) > 0) &&
         (version_in_range(version:dllVer2, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34291")))
      {
        VULN = TRUE ;
        vulnerable_range = "4.0.30319.34000 - 4.0.30319.34291";
      }

      ## .NET Framework 4.5.2 in Windows 8.1, Windows RT 8.1, and Windows Server 2012 R2
      ##  not supporting Windows Server 2012 R2
      else if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_in_range(version:dllVer2, test_version:"4.0.30319.34000", test_version2:"4.0.30319.36345")))
      {
        VULN = TRUE ;
        vulnerable_range = "4.0.30319.34000 - 4.0.30319.36345";
      }

      ## .NET Framework 4.6 and 4.6.1 in Windows 8.1, Windows RT 8.1, and Windows Server 2012 R2
      else if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1) > 0) &&
        (version_in_range(version:dllVer2, test_version:"4.6.1000.0", test_version2:"4.6.1072.0")))
      {
        VULN = TRUE ;
        vulnerable_range = "4.6.1000.0 - 4.6.1072.0";
      }

      ## .NET Framework 4.6 and 4.6.1 in Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      else if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer2, test_version:"4.6.1000.0", test_version2:"4.6.1070.0")))
      {
        VULN = TRUE ;
        vulnerable_range = "4.6.1000.0 - 4.6.1070.0";
      }
    } ## System.Security.dll - END
  }
}

if(VULN)
{
  report = 'File checked:     ' + path + "System.Security.dll" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";

##.NET Framework 3.5 on Windows 8 and Windows Server 2012
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"System.printing.dll");
    if(dllVer)
    {
      ##NET Framework 3.5 in Windows 8.1
      if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.0.6920.8700", test_version2:"3.0.6920.8701"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.8700 - 3.0.6920.8701";
        }

        if(version_in_range(version:dllVer, test_version:"3.0.6920.8000", test_version2:"3.0.6920.8009"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.8000 - 3.0.6920.8009";
        }
      }

      # .NET Framework 3.5 in Windows Server 2012
      else if(hotfix_check_sp(win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.0.6920.6400", test_version2:"3.0.6920.6422"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.6400 - 3.0.6920.6422";
        }

        if(version_in_range(version:dllVer, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8698"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.8600 - 3.0.6920.8698";
        }
      }

      ## Framework 3.0 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.0.6920.5400", test_version2:"3.0.6920.5470"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.5400 - 3.0.6920.5470";
        }

        if(version_in_range(version:dllVer, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8698"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.8600 - 3.0.6920.8698";
        }
      }

      # .NET Framework 3.0 Service Pack 2 in Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4230"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.4000 - 3.0.6920.4230";
        }

        else if(version_in_range(version:dllVer, test_version:"3.0.6920.8000", test_version2:"3.0.6920.8701"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "3.0.6920.8000 - 3.0.6920.8701";
        }
      }
    }
  }
}

if(VULN1)
{
  report = 'File checked:     ' + path + "System.printing.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
}
