###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Multiple Vulnerabilities (2916607)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903337");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-0253", "CVE-2014-0257", "CVE-2014-0295");
  script_bugtraq_id(65415, 65417, 65418);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-02-12 10:37:08 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (2916607)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS14-009.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - ASP.NET does not properly identify stale HTTP connections.

  - An error within the .NET framework when handling certain COM objects.

  - Additionally, some unspecified weakness exists.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
mechanism and cause denial of service.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 1.0, 1.1, 2.0, 3.0, 3.5, 3.5.1, 4.0, 4.5 and 4.5.1");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56793");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2916607");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-009");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1) <= 0){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## .NET Framework 1.1 Service Pack 1 for Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2503")))
      {
        VULN1 = TRUE;
        Vulnerable_range = "1.1.4322.2000 - 1.1.4322.2503";
      }

      ## .NET Framework 2.0 Service Pack 2 for Windows XP Service Pack 3 and Windows Server 2003 Service Pack 2
      if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3654"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.3000 - 2.0.50727.3654";
        }

        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7040";
        }
      }

      ## .NET Framework 2.0 Service Pack 2 for Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4246"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.4000 - 2.0.50727.4246";
        }

        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7040";
        }
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6412"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.6000 - 2.0.50727.6412";
        }
        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7040";
        }
      }

      ## .NET Framework 3.5 for Windows 8.1
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_is_less(version:dllVer, test_version:"2.0.50727.8000")))
      {
        VULN1 = TRUE;
        Vulnerable_range = "Less than 2.0.50727.8000";
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5476"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.5400 - 2.0.50727.5476";
        }
        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7040";
        }
      }

      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista,
      if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1021"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.1000 - 4.0.30319.1021";
        }
        else if(version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2033"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.2000 - 4.0.30319.2033";
        }
      }
      ## .NET Framework 4.5 for Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18062"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18062";
        }
        if(version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19131"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.19000 - 4.0.30319.19131";
        }
      }

      ## .NET Framework 4.5 for Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18448"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18448";
        }
        if(version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19454"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.19000 - 4.0.30319.19454";
        }
      }

      ## .NET Framework 4.5.1 for Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18443")))
      {
        VULN1 = TRUE;
        Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18443";
      }

      ## .NET Framework 4.5.1 for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18448")))
      {
        VULN1 = TRUE;
        Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18448";
      }

      ## .NET Framework 4.5.1 for Windows 8.1
      if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34010"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.34000 - 4.0.30319.34010";
        }
        else if(version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36012"))
        {
          VULN1 = TRUE;
          Vulnerable_range = "4.0.30319.36000 - 4.0.30319.36012";
        }
      }
    } ## mscorlib.dll - END



    dllVer = fetch_file_version(sysPath:path, file_name:"System.Web.dll");
    if(dllVer)
    {
      ## .NET Framework 1.1 Service Pack 1 for Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
        (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2504")))
      {
        VULN2 = TRUE;
        Vulnerable_range = "1.1.4322.2000 - 1.1.4322.2504";
      }

      ## .NET Framework 2.0 Service Pack 2 for Windows XP Service Pack 3 and Windows Server 2003 Service Pack 2
      if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3657"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.3000 - 2.0.50727.3657";
        }

        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7045"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7045";
        }
      }
      ## .NET Framework 2.0 Service Pack 2 for Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4247"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.4000 - 2.0.50727.4247";
        }
        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7044"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7044";
        }
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6413"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.6000 - 2.0.50727.6413";
        }
        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7044"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7044";
        }
      }

      ## .NET Framework 3.5 for Windows 8.1
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_is_less(version:dllVer, test_version:"2.0.50727.8001")))
      {
        VULN2 = TRUE;
        Vulnerable_range = "Less than 2.0.50727.8001";
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5478"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.5400 - 2.0.50727.5478";
        }
        else if(version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7044"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "2.0.50727.7000 - 2.0.50727.7044";
        }
      }

      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista,
      if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1021"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.1000 - 4.0.30319.1021";
        }
        if(version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2033"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.2000 - 4.0.30319.2033";
        }
      }
      ## .NET Framework 4.5 for Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18066"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18066";
        }
        if(version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19135"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.19000 - 4.0.30319.19135";
        }
      }
      ## .NET Framework 4.5 for Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18448"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18448";
        }
        if(version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19454"))
        {
          VULN2 = TRUE;
          Vulnerable_range = "4.0.30319.19000 - 4.0.30319.19454";
        }
      }

      ## .NET Framework 4.5.1 for Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18445")))
      {
        VULN2 = TRUE;
        Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18445";
      }

      ## .NET Framework 4.5.1 for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18446")))
      {
        VULN2 = TRUE;
        Vulnerable_range = "4.0.30319.18000 - 4.0.30319.18446";
      }

      ## .NET Framework 4.5.1 for Windows 8.1
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34008")))
      {
        VULN2 = TRUE;
        Vulnerable_range = "4.0.30319.34000 - 4.0.30319.34008";
      }

    } ## System.Web.dll - END



    dllVer = fetch_file_version(sysPath:path, file_name:"vsavb7rt.dll");
    if(dllVer)
    {
      ## .NET Framework 2.0 Service Pack 2 for Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"8.0.50727.4000", test_version2:"8.0.50727.4249"))
        {
          VULN3 = TRUE;
          Vulnerable_range = "8.0.50727.4000 - 8.0.50727.4249";
        }
        else if(version_in_range(version:dllVer, test_version:"8.0.50727.7000", test_version2:"8.0.50727.7050"))
        {
          VULN3 = TRUE;
          Vulnerable_range = "8.0.50727.7000 - 8.0.50727.7050";
        }
      }
      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"8.0.50727.5400", test_version2:"8.0.50727.5480"))
        {
          VULN3 = TRUE;
          Vulnerable_range = "8.0.50727.5400 - 8.0.50727.5480";
        }
        if(version_in_range(version:dllVer, test_version:"8.0.50727.7000", test_version2:"8.0.50727.7050"))
        {
          VULN3 = TRUE;
          Vulnerable_range = "8.0.50727.7000 - 8.0.50727.7050";
        }
      }

    } ## vsavb7rt.dll - END

  }
}

if(VULN1)
{
  report = 'File checked:     ' + path + "\mscorlib.dll" + '\n' +
           'File version:     ' + dllVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range+ '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + path + "\System.Web.dll" + '\n' +
           'File version:     ' + dllVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range+ '\n' ;
  security_message(data:report);
}

if(VULN3)
{
  report = 'File checked:     ' + path + "\vsavb7rt.dll" + '\n' +
           'File version:     ' + dllVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range+ '\n' ;
  security_message(data:report);
  exit(0);
}
