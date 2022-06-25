###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Denial of Service Vulnerabilities (3137893)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806681");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0033", "CVE-2016-0047");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-10 10:38:07 +0530 (Wed, 10 Feb 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft .NET Framework Denial of Service Vulnerabilities (3137893)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-019.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Application fails to properly handle certain Extensible Stylesheet
    Language Transformations (XSLT).

  - The .NET's Windows Forms (WinForms) improperly handles icon data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information or disrupt the availability of
  applications that use the .NET framework.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 2.0 Service Pack 2,

  Microsoft .NET Framework 3.5,

  Microsoft .NET Framework 3.5.1,

  Microsoft .NET Framework 4.5.2,

  Microsoft .NET Framework 4.6 and 4.6.1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3137893");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-019");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3,
   win2008r2:2, win8:1, win8x64:1, win2012:1, win2012R2:1,
   win10:1, win10x64:1) <= 0){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"System.Xml.dll");
    dllVer2 = fetch_file_version(sysPath:path, file_name:"System.Drawing.dll");

    ##If either file information is available
    if(dllVer || dllVer2)
    {
      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122646
        if(version_is_less(version:dllVer, test_version:"2.0.50727.4260"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.4260";
        }

        if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8678"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8678";
        }

        ## https://support.microsoft.com/en-us/kb/3127219
        if(version_is_less(version:dllVer2, test_version:"2.0.50727.4261"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.4261";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8680"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
        }
      }

      ## .NET Framework 3.5 and 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122648
        if(version_is_less(version:dllVer, test_version:"2.0.50727.5494"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.5494";
        }

        if(version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8678"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "2.0.50727.8600 - 2.0.50727.8678";
        }

        ## https://support.microsoft.com/en-us/kb/3127220
        if(version_is_less(version:dllVer2, test_version:"2.0.50727.5495"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.5495";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8680"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
        }
      }

      ## .NET Framework 3.5 on Windows Server 2012
      if(hotfix_check_sp(win2012:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3122649
        if(version_is_less(version:dllVer, test_version:"2.0.50727.6430"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.6430";
        }

        if(version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8678"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "2.0.50727.8000 - 2.0.50727.8678";
        }

        ##https://support.microsoft.com/en-us/kb/3127221
        if(version_is_less(version:dllVer2, test_version:"2.0.50727.6431"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.6431";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8680"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
        }
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3122651
        if(version_is_less(version:dllVer, test_version:"2.0.50727.8018"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.8018";
        }

        if(version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8678"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "2.0.50727.8600 - 2.0.50727.8678";
        }

        ## https://support.microsoft.com/en-us/kb/3127222
        if(version_is_less(version:dllVer2, test_version:"2.0.50727.8019"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "Less than 2.0.50727.8019";
        }

        if(version_in_range(version:dllVer2, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8680"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
        }
      }

      ## .NET Framework 4.5.2 on Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      ##  Windows 7 Service Pack 1, and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122656
        if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.34282"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.34282";
        }

        if(version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36335"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.0.30319.36000 - 4.0.30319.36335";
        }

        ## https://support.microsoft.com/en-us/kb/3127229
        if(version_in_range(version:dllVer2, test_version:"4.0.30319.30000", test_version2:"4.0.30319.34284"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.34284";
        }

        if(version_in_range(version:dllVer2, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36337"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.0.30319.36000 - 4.0.30319.36337";
        }
      }

      ## .NET Framework 4.5.2 on Windows Server 2012
      ## .NET Framework 4.5.2 on Windows 8.1 and Windows Server 2012 R2
      if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122655 and https://support.microsoft.com/en-us/kb/3122654
        if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.34280"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.34280";
        }

        if(version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36333"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.0.30319.36000 - 4.0.30319.36333";
        }

       ## https://support.microsoft.com/en-us/kb/3127227 and https://support.microsoft.com/en-us/kb/3127226
       if(version_in_range(version:dllVer2, test_version:"4.0.30319.30000", test_version2:"4.0.30319.34283"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.34283";
        }

        if(version_in_range(version:dllVer2, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36336"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.0.30319.36000 - 4.0.30319.36336";
        }
      }

      ## .NET Framework 4.6 and 4.6.1 on Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      ##  Windows 7 Service Pack 1, and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122661
        ## After patch Installed version is 4.6.1067.0, not 4.6.1067.4 as mentioned in KB-3122661
        if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.6.1066"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.6 - 4.6.1066";
        }
      }

      ## .NET Framework 4.6 and 4.6.1 in Windows Server 2012
      ## .NET Framework 4.6 and 4.6.1 in Windows 8.1, and Windows Server 2012 R2
      if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3122658 and https://support.microsoft.com/en-us/kb/3122660
        if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.6.1064.1"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.6 - 4.6.1064.1";
        }

        ## https://support.microsoft.com/en-us/kb/3127230 and https://support.microsoft.com/en-us/kb/3127231
        if(version_in_range(version:dllVer2, test_version:"4.6", test_version2:"4.6.1068.1"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.6 - 4.6.1068.1";
        }
      }

      ## .NET Framework on Windows 10
      if(hotfix_check_sp(win10:1, win10x64:1) > 0)
      {
        ##https://support.microsoft.com/en-us/kb/3135173 and https://support.microsoft.com/en-us/kb/3135174
        if(version_is_less(version:dllVer, test_version:"2.0.50727.8679"))
        {
          vulnerable_range = "Less than 2.0.50727.8679";
          VULN1 = TRUE ;
        }

        if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.6.1064.1"))
        {
          VULN1  = TRUE ;
          vulnerable_range = "4.6 - 4.6.1064.1";
        }

        ##https://support.microsoft.com/en-us/kb/3135174 and ##https://support.microsoft.com/en-us/kb/3135173
        if(version_is_less(version:dllVer2, test_version:"2.0.50727.8681"))
        {
          vulnerable_range = "Less than 2.0.50727.8681";
          VULN2 = TRUE ;
        }

        if(version_in_range(version:dllVer2, test_version:"4.6", test_version2:"4.6.1068.1"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "4.6 - 4.6.1068.1";
        }
      }
    }

    ## .NET Framework 4.6 on Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, and Windows Server 2008 R2 SP1
    ##  and the .NET Framework 4.6.1 on Windows 7 SP1 and Windows Server 2008 R2 SP1
    ## https://support.microsoft.com/en-us/kb/3127233

    ## Path for file Setupui.dll for .NET 4.6 == ...Microsoft.NET\Framework\v4.0.30319\SetupCache\v4.6.00081
    dllVer3 = fetch_file_version(sysPath:path, file_name:"\SetupCache\v4.6.00081\SetupUi.dll");
    if(dllVer3)
    {
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        ## https://support.microsoft.com/en-us/kb/3127233
        if(version_is_less(version:dllVer3, test_version:"14.0.1068.2"))
        {
          VULN3 = TRUE ;
          vulnerable_range = "Less than 14.0.1068.2";
        }
      }
    }
  }
}

if(VULN1)
{
  report = 'File checked:     ' + path + "System.Xml.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + path + "System.Drawing.dll" + '\n' +
           'File version:     ' + dllVer2 + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + path + "\SetupCache\v4.6.00081\SetupUi.dll" + '\n' +
           'File version:     ' + dllVer3  + '\n' +
           'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report);
}

