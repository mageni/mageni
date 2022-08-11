###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Graphics Component Multiple Vulnerabilities (4013075)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810811");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0001", "CVE-2017-0005", "CVE-2017-0025", "CVE-2017-0047",
                "CVE-2017-0060", "CVE-2017-0062", "CVE-2017-0073", "CVE-2017-0061",
                "CVE-2017-0063", "CVE-2017-0038", "CVE-2017-0108", "CVE-2017-0014");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 11:04:14 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Graphics Component Multiple Vulnerabilities (4013075)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-013.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - The way the Windows Graphics Device Interface (GDI) handles objects in memory.

  - The Windows GDI component improperly discloses the contents of its memory.

  - The way that the Color Management Module (ICM32.dll) handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform remote code execution, gain access to potentially sensitive
  information and gain elevated privileges.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x86/x64

  Microsoft Windows XP SP2 x64 / SP3 x86

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 10/1511/1607 x32/x64

  Microsoft Windows Server 2012/2012R2/2016

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4013075");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-013");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1, win2016:1, win8:1, win8x64:1, xp:4, xpx64:3, win2003:3,
                   win2003x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

uspVer = fetch_file_version(sysPath:sysPath, file_name:"Usp10.dll");
winVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
icmVer = fetch_file_version(sysPath:sysPath, file_name:"icm32.dll");
gdiVer = fetch_file_version(sysPath:sysPath, file_name:"gdi32.dll");

if(!uspVer && !winVer && !icmVer && !gdiVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
    ## Presently GDR information is not available.
    if(winVer && version_is_less(version:winVer, test_version:"6.1.7601.23677"))
    {
      Vulnerable_range = "Less than 6.1.7601.23677";
      VULN = TRUE ;
    }
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
    if(winVer && version_is_less(version:winVer, test_version:"6.0.6002.19741"))
    {
      Vulnerable_range = "Less than 6.0.6002.19741";
      VULN = TRUE ;
    }

    else if(winVer && version_in_range(version:winVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24064"))
    {
      Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24064";
      VULN = TRUE ;
    }

    else if(uspVer && version_is_less(version:uspVer, test_version:"1.626.6002.19743"))
    {
      Vulnerable_range1 = "Less than 1.626.6002.19743";
      VULN1 = TRUE ;
    }

    else if(uspVer && version_in_range(version:uspVer, test_version:"1.626.6002.24000", test_version2:"1.626.6002.24066"))
    {
      Vulnerable_range1 = "1.626.6002.24000 - 1.626.6002.24066";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(winVistax64:3, win2008x64:3) > 0)
{
   if(icmVer && version_is_less(version:icmVer, test_version:"6.0.6002.19741"))
   {
     Vulnerable_range2 = "Less than 6.0.6002.19741";
     VULN2 = TRUE ;
   }

   else if(winVer && version_in_range(version:icmVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24064"))
   {
     Vulnerable_range2 = "6.0.6002.24000 - 6.0.6002.24064";
     VULN2 = TRUE ;
   }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(winVer && version_is_less(version:winVer, test_version:"6.2.9200.22097"))
  {
     Vulnerable_range = "Less than 6.2.9200.22097";
     VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(winVer && version_is_less(version:winVer, test_version:"6.3.9600.18603"))
  {
    Vulnerable_range = "Less than 6.3.9600.18603";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  if(winVer && version_is_less(version:winVer, test_version:"10.0.10240.16384") )
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN = TRUE;
  }

  else if(winVer && version_in_range(version:winVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
    VULN = TRUE ;
  }

  else if( winVer && version_in_range(version:winVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.593"))
  {
    Vulnerable_range = "10.0.14393.0 - 10.0.14393.593";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  if(gdiVer && version_is_less(version:gdiVer, test_version:"5.1.2600.7209"))
  {
    Vulnerable_range3 = "Less than 5.1.2600.7209";
    VULN3 = TRUE ;
  }
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(gdiVer && version_is_less(version:gdiVer, test_version:"5.2.3790.6022"))
  {
    Vulnerable_range3 = "Less than 5.2.3790.6022";
    VULN3 = TRUE ;
  }
}

else if(hotfix_check_sp(win8:1, win8x64:1) > 0)
{
  if(gdiVer && version_is_less(version:gdiVer, test_version:"6.2.9200.22084"))
  {
    Vulnerable_range3 = "Less than 6.2.9200.22084";
    VULN3 = TRUE ;
  }
}



if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Win32k.sys" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\Usp10.dll" + '\n' +
           'File version:     ' + uspVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\icm32.dll" + '\n' +
           'File version:     ' + icmVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\gdi32.dll" + '\n' +
           'File version:     ' + gdiVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
