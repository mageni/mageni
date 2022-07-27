###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-081.nasl 32358 2013-10-09 09:00:42Z oct$
#
# MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2870008)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903500");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880",
                "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894");
  script_bugtraq_id(62819, 62823, 62828, 62833, 62830, 62831, 62821);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-10-09 09:16:37 +0530 (Wed, 09 Oct 2013)");
  script_name("MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2870008)");

  script_tag(name:"summary", value:"This host is missing an critical security
  update according to Microsoft Bulletin MS13-081");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - An error when parsing OpenType fonts (OTF) can be exploited to corrupt
    memory.

  - An error when handling the USB descriptor of inserted USB devices can be
    exploited to corrupt memory.

  - A use-after-free error within the kernel-mode driver (win32k.sys) can be
    exploited to gain escalated privileges.

  - An error when handling objects in memory related to App Containers can
    be exploited to disclose information from a different App Container.

  - An error related to NULL page handling within the kernel-mode driver
    (win32k.sys) can be exploited to gain escalated privileges.

  - A double fetch error within the DirectX graphics kernel subsystem
    (dxgkrnl.sys) can be exploited to gain escalated privileges.

  - An error when parsing the CMAP table while rendering TrueType
    fonts (TTF) can be exploited to corrupt memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code with kernel-mode privileges and take
  complete control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 8

  Microsoft Windows Server 2012

  Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55052/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2862330");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-081");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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
  win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

atmfdVer = fetch_file_version(sysPath:sysPath, file_name:"atmfd.dll");
usbdSysVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\usbd.sys");
hidparseVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\hidparse.sys");
win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
fontsubVer = fetch_file_version(sysPath:sysPath, file_name:"Fontsub.dll");
dwVer = fetch_file_version(sysPath:sysPath, file_name:"Dwrite.dll");
cddVer  = fetch_file_version(sysPath:sysPath, file_name:"cdd.dll");
wdVer = fetch_file_version(sysPath:sysPath, file_name:"Wdfres.dll");

if(usbdSysVer || atmfdVer ||  hidparseVer ||
   win32SysVer ||  dwVer || cddVer || wdVer)
{

  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:atmfdVer, test_version:"5.1.2.236") && (atmfdVer)){
      Vulnerable_range_atmfd = "Less than 5.1.2.236";
    }

    else if(version_is_less(version:usbdSysVer, test_version:"5.1.2600.6437") && (usbdSysVer)){
      Vulnerable_range_usbdSys = "Less than 5.1.2600.6437";
    }

    else if(version_is_less(version:hidparseVer, test_version:"5.1.2600.6418") && (hidparseVer)){
      Vulnerable_range_hidparse = "Less than 5.1.2600.6418";
    }

    else if(version_is_less(version:win32SysVer, test_version:"5.1.2600.6442") && (win32SysVer)){
      Vulnerable_range_win32Sys = "Less than 5.1.2600.6442";
    }
  }

  if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
  {
    if(version_is_less(version:atmfdVer, test_version:"5.1.2.236") && (atmfdVer)){
      Vulnerable_range_atmfd = "Less than 5.1.2.236";
    }

    else if(version_is_less(version:usbdSysVer, test_version:"5.2.3790.5203") && (usbdSysVer)){
      Vulnerable_range_usbdSys = "Less than 5.2.3790.5203";
    }

    else if(version_is_less(version:hidparseVer, test_version:"5.2.3790.5189") && (hidparseVer)){
      Vulnerable_range_hidparse = "Less than 5.2.3790.5189";
    }

    else if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5216") && (win32SysVer)){
      Vulnerable_range_win32Sys = "Less than 5.2.3790.5216";
    }
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(fontsubVer)
    {
      if(version_is_less(version:fontsubVer, test_version:"6.0.6002.18272")){
        Vulnerable_range_fontsub = "Less than 6.0.6002.18272";
      }

      else if(version_in_range(version:fontsubVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23131")){
        Vulnerable_range_fontsub = "6.0.6002.22000 - 6.0.6002.23131";
      }
    }

    if(usbdSysVer)
    {
      if(version_is_less(version:usbdSysVer, test_version:"6.0.6002.18875")){
        Vulnerable_range_usbdSys = "Less than 6.0.6002.18875";
      }

      else if(version_in_range(version:usbdSysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23146")){
        Vulnerable_range_usbdSys = "6.0.6002.22000 - 6.0.6002.23146";
      }
    }

    if(hidparseVer)
    {
      if(version_is_less(version:hidparseVer, test_version:"6.0.6002.18878")){
        Vulnerable_range_hidparse = "Less than 6.0.6002.18878";
      }

      else if(version_in_range(version:hidparseVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23149")){
        Vulnerable_range_hidparse = "6.0.6002.22000 - 6.0.6002.23149";
      }
    }

    if(win32SysVer)
    {
      if(version_is_less(version:win32SysVer, test_version:"6.0.6002.18927")){
        Vulnerable_range_win32Sys = "Less than 6.0.6002.18927";
      }
      else if(version_in_range(version:win32SysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23203")){
        Vulnerable_range_win32Sys = "6.0.6002.22000 - 6.0.6002.23203";
      }
    }

    if(dwVer)
    {
      if(version_is_less(version:dwVer, test_version:"7.0.6002.18923")){
        Vulnerable_range_dwrite = "Less than 7.0.6002.18923";
      }

      else if(version_in_range(version:dwVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23199")){
        Vulnerable_range_dwrite = "7.0.6002.22000 - 7.0.6002.23199";
      }
    }

    if(cddVer)
    {
      if(version_is_less(version:cddVer, test_version:"7.0.6002.18392")){
        Vulnerable_range_cdd = "Less than 7.0.6002.18392";
      }

      else if (version_in_range(version:cddVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23180")){
        Vulnerable_range_cdd = "7.0.6002.22000 - 7.0.6002.23180";
      }
    }

    if(wdVer)
    {
      if(version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
        Vulnerable_range_wd = "Less than 6.2.9200.16384" ;
      }

##      else if(version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384")){
##        Vulnerable_range_wd = "6.2.9200.16000 - 6.2.9200.16384";
##      }
    }
  }

  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(fontsubVer)
    {
      if(version_is_less(version:fontsubVer, test_version:"6.1.7601.18177")){
        Vulnerable_range_fontsub = "Less than 6.1.7601.18177";
      }

      else if(version_in_range(version:fontsubVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22349")){
        Vulnerable_range_fontsub = "6.1.7601.22000 - 6.1.7601.22349" ;
      }
    }

    if(usbdSysVer)
    {
      if(version_is_less(version:usbdSysVer, test_version:"6.1.7601.18251")){
        Vulnerable_range_usbdSys = "Less than 6.1.7601.18251";
      }

      else if(version_in_range(version:usbdSysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22440")){
        Vulnerable_range_usbdSys = "6.1.7601.22000 - 6.1.7601.22440";
      }
    }

    if(hidparseVer)
    {
      if(version_is_less(version:hidparseVer, test_version:"6.1.7601.18199")){
        Vulnerable_range_hidparse = "Less than 6.1.7601.18199";
      }
      else if(version_in_range(version:hidparseVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22373")){
        Vulnerable_range_hidparse = "6.1.7601.22000 - 6.1.7601.22373";
      }
    }

    if(win32SysVer)
    {
      if(version_is_less(version:win32SysVer, test_version:"6.1.7601.18246")){
        Vulnerable_range_win32Sys = "Less than 6.1.7601.18246";
      }
      else if(version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22434")){
        Vulnerable_range_win32Sys = "6.1.7601.22000 - 6.1.7601.22434";
      }
    }

    if(dwVer)
    {
      if(version_is_less(version:dwVer, test_version:"6.1.7601.18245")){
        Vulnerable_range_dwrite = "Less than 6.1.7601.18245";
      }
      else if(version_in_range(version:dwVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22433")){
        Vulnerable_range_dwrite = "6.1.7601.22000 - 6.1.7601.22433";
      }
    }

    if(cddVer)
    {
      if(version_is_less(version: cddVer, test_version:"6.1.7601.17514")){
        Vulnerable_range_cdd = "Less than 6.1.7601.17514";
      }

      else if (version_in_range(version: cddVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.17513")){
        Vulnerable_range_cdd = "6.1.7601.22000 - 6.1.7601.17513";
      }
    }

    if(wdVer)
    {
      if(version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
        Vulnerable_range_wd = "Less than 6.2.9200.16384";
      }

#      else if(version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384")){
#        Vulnerable_range_wd = "6.2.9200.16000 - 6.2.9200.16384";
#      }
    }
  }

  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    if(fontsubVer)
    {
      if(version_is_less(version:fontsubVer, test_version:"6.2.9200.16453")){
        Vulnerable_range_fontsub = "Less than 6.2.9200.16453";
      }
#      else if(version_in_range(version:fontsubVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.16383")){
#        Vulnerable_range_fontsub = "6.2.9200.20000 - 6.2.9200.16383";
#      }
    }

    if(usbdSysVer)
    {
      if(version_is_less(version:usbdSysVer, test_version:"6.2.9200.16654")){
        Vulnerable_range_usbdSys = "Less than 6.2.9200.16654";
      }

      else if (version_in_range(version:usbdSysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20760")){
        Vulnerable_range_usbdSys = "6.2.9200.20000 - 6.2.9200.20760";
      }
    }

    if(hidparseVer)
    {
      if(version_is_less(version:hidparseVer, test_version:"6.2.9200.16654")){
        Vulnerable_range_hidparse = "Less than 6.2.9200.16654";
      }
      else if (version_in_range(version:hidparseVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20762")){
        Vulnerable_range_hidparse = "6.2.9200.20000 - 6.2.9200.20762";
      }
    }

    if(win32SysVer)
    {
      if(version_is_less(version:win32SysVer, test_version:"6.2.9200.16699")){
        Vulnerable_range_win32Sys = "Less than 6.2.9200.16699";
      }

      else if(version_in_range(version:win32SysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20806")){
        Vulnerable_range_win32Sys = "6.2.9200.20000 - 6.2.9200.20806";
      }
    }

    if(wdVer)
    {
      if(version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
        Vulnerable_range_wd = "Less than 6.2.9200.16384";
      }
#      else if(version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384")){
#        Vulnerable_range_wd = "6.2.9200.16000 - 6.2.9200.16384";
#      }
    }
  }
}

if(Vulnerable_range_atmfd)
{
  report = 'File checked:     ' + sysPath + "\atmfd.dll" + '\n' +
           'File version:     ' + atmfdVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_atmfd + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_usbdSys)
{
  report = 'File checked:     ' + sysPath + "\drivers\usbd.sys" + '\n' +
           'File version:     ' + usbdSysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_usbdSys + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_hidparse)
{
  report = 'File checked:     ' + sysPath + "drivers\hidparse.sys" + '\n' +
           'File version:     ' + hidparseVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_hidparse + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_win32Sys)
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + win32SysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_win32Sys + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_fontsub)
{
  report = 'File checked:     ' + sysPath + "\Fontsub.dll" + '\n' +
           'File version:     ' + fontsubVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_fontsub + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_dwrite)
{
  report = 'File checked:     ' + sysPath + "\Dwrite.dll" + '\n' +
           'File version:     ' + dwVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_dwrite + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_cdd)
{
  report = 'File checked:     ' + sysPath + "\cdd.dll" + '\n' +
           'File version:     ' + cddVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_cdd + '\n' ;
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range_wd)
{
  report = 'File checked:     ' + sysPath + "\Wdfres.dll" + '\n' +
           'File version:     ' + wdVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range_wd + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
