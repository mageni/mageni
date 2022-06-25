###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Wireless Mouse Input Filtering Improvement Advisory (3152550)
#
# Authors:
# Rinu kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807544");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-04-14 14:33:32 +0530 (Thu, 14 Apr 2016)");
  script_name("Microsoft Wireless Mouse Input Filtering Improvement Advisory (3152550)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3152550).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An update is available that improve
  input filtering for certain microsoft wireless mouse devices. The update
  enhances security by filtering out QWERTY key packets in keystroke
  communications issued from receiving USB wireless dongles to wireless mouse
  devices.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to inject arbitrary keyboard HID packets (for example, to simulate
  keystrokes) into a USB dongle.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows 7 x32/x64 Edition Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  ##qod is executable_version_unreliable as only Microsoft wireless devices are affected
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3152550");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/3152550.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win7:2, win7x64:2, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## The vulnerable files are not found in the system.So developed taking the default location on assumption
sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Drivers\Wirelesskeyboardfilter.sys");
dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Wirelessdevice.dll");

if(!sysVer && !dllVer1){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win7:2, win7x64:2, win10:1, win10x64:1) > 0)
{
  if(sysVer && version_is_less(version:sysVer, test_version:"1.0.102.0"))
  {
    Vulnerable_range = "Version Less than 1.0.102.0";
    VULN1 = TRUE ;
  }

  if(dllVer1 && version_is_less(version:dllVer1, test_version:"1.0.102.0"))
  {
    Vulnerable_range = "Version Less than 1.0.102.0";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Drivers\Wirelesskeyboardfilter.sys" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Wirelessdevice.dll" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
