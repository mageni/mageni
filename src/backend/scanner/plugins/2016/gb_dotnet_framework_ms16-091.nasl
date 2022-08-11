###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Information Disclosure Vulnerability (3170048)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807856");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3255");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-07-13 08:15:13 +0530 (Wed, 13 Jul 2016)");
  script_name("Microsoft .NET Framework Information Disclosure Vulnerability (3170048)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-091.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as .NET Framework improperly
  parses XML input containing a reference to an external entity.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 2.0 Service Pack 2

  Microsoft .NET Framework 3.5

  Microsoft .NET Framework 3.5.1

  Microsoft .NET Framework 4.5.2

  Microsoft .NET Framework 4.6/4.6.1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3170048");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3163912");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3172985");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-091");

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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3,
   win2008x64:3, win2008r2:2, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1,
   win10:1, win10x64:1) <= 0){
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
    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"system.data.dll");
    if(sysdllVer)
    {
      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      ## https://support.microsoft.com/en-us/kb/3163244
      if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
      {
        if(version_is_less(version:sysdllVer, test_version:"2.0.50727.4265"))
        {
          VULN = TRUE ;
          vulnerable_range = "Less than 2.0.50727.4265";
        }

        else if(version_in_range(version:sysdllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8691"))
        {
          VULN = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8691";
        }
      }

      ## .NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      ## .NET Framework 3.5 in Windows 8.1 and Windows Server 2012 R2
      ## .NET Framework 3.5 in Windows Server 2012
      ## Only LDR is given, combining ranges
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3163245
        ##https://support.microsoft.com/en-us/kb/3163246
        ##https://support.microsoft.com/en-us/kb/3163247
        if(version_is_less(version:sysdllVer, test_version:"2.0.50727.8692"))
        {
          VULN = TRUE ;
          vulnerable_range = "Less than 2.0.50727.8692";
        }
      }

      ## .NET Framework 4.5.2 on Windows Server 2012
      ## .NET Framework 4.5.2 in Windows 8.1, and Windows Server 2012 R2
      ## https://support.microsoft.com/en-us/kb/3163250
      ## https://support.microsoft.com/en-us/kb/3163291
      if(hotfix_check_sp(win2012:1, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
      {
        if(version_in_range(version:sysdllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36360"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.36360";
        }
      }

      ##.NET Framework 4.5.2 in Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      ## https://support.microsoft.com/en-us/kb/3163251
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
      {
        if(version_in_range(version:sysdllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.34296"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.34296";
        }

        else if(version_in_range(version:sysdllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36359"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.0.30319.36000 - 4.0.30319.36359";
        }
      }

      ##.NET Framework 4.6 in Windows Vista SP2 and Windows Server 2008 SP2 and
      ##.NET Framework 4.6 and 4.6.1 in Windows 7 SP1 and Windows Server 2008 R2 SP1
      ##.NET Framework 4.6 and 4.6.1 in Windows Server 2012
      ##.NET Framework 4.6 and 4.6.1 in Windows 8.1, and Windows Server 2012 R2
      if(hotfix_check_sp(win2012:1, win7:2, win7x64:2, win2008r2:2,
            winVista:3, winVistax64:3, win2008:3, win2008x64:3, win8_1:1,
            win8_1x64:1, win2012R2:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3164024
        ##https://support.microsoft.com/en-us/kb/3164023
        ##https://support.microsoft.com/en-us/kb/3164025
        if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.6.1081"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.6 - 4.6.1081";
        }
      }

      ## .NET Framework on Windows 10
      if(hotfix_check_sp(win10:1, win10x64:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3172985
        ##https://support.microsoft.com/en-us/kb/3163912
        if(version_is_less(version:sysdllVer, test_version:"2.0.50727.8692"))
        {
          vulnerable_range = "Less than 2.0.50727.8692";
          VULN = TRUE ;
        }
        if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.6.1081"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.6 - 4.6.1081";
        }
      }
    }
  }

  if(VULN)
  {
    report = 'File checked:     ' + dotPath + "\System.Data.dll" + '\n' +
             'File version:     ' + sysdllVer  + '\n' +
             'Vulnerable range: ' + vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
