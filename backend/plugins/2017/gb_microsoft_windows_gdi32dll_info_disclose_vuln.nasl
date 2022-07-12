###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Graphics Component 'gdi32.dll' Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.809889");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0038");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-02-21 17:10:32 +0530 (Tue, 21 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Graphics Component 'gdi32.dll' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with 'gdi32.dll'
  Graphics Device Interface which is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to multiple bugs related
  to the handling of DIBs (Device Independent Bitmaps) embedded in EMF records.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain sensitive information from process heap memory.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511, 1607 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=992");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-013");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

##Reference nvt gb_ms16-074.nasl
##Version is checked as less and equal here, as the vulnerability was not patched properly

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllver1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Gdi32.dll");
if(!dllver1){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
    if(version_is_less_equal(version:dllver1, test_version:"6.1.7601.23457"))
    {
      Vulnerable_range = "Version 6.1.7601.23457 and prior";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(winVista:3, win2008:3, win2008x64:3, winVistax64:3) > 0)
{
    if(version_is_less_equal(version:dllver1, test_version:"6.0.6002.19660"))
    {
      Vulnerable_range = "Version 6.0.6002.19660 and prior";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllver1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23975"))
    {
      Vulnerable_range = "6.0.6002.23000 - 6.0.6002.6.0.6002.23975";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
    if(version_is_less_equal(version:dllver1, test_version:"6.3.9600.18344"))
    {
      Vulnerable_range = "Version 6.3.9600.18344 and prior";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
    if(version_is_less_equal(version:dllver1, test_version:"6.2.9200.21881"))
    {
      Vulnerable_range = "Version 6.2.9200.21881 and prior";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
    if(version_is_less_equal(version:dllver1, test_version:"10.0.10240.16942"))
    {
      Vulnerable_range = "Version 10.0.10240.16942 and prior";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllver1, test_version:"10.0.10586.0", test_version2:"10.0.10586.420"))
    {
      Vulnerable_range = "10.0.10586.0 - 10.0.10586.420";
      VULN1 = TRUE ;
    }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Gdi32.dll" + '\n' +
           'File version:     ' + dllver1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
