###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Remote Desktop Elevation of Privilege Vulnerability (3134700)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:rdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807064");
  script_version("2019-05-20T06:45:30+0000");
  script_cve_id("CVE-2016-0036");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 06:45:30 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-10 09:02:28 +0530 (Wed, 10 Feb 2016)");
  script_name("Microsoft Windows Remote Desktop Elevation of Privilege Vulnerability (3134700)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-017.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to mishandling of
  objects in memory by RDP and that is triggered when an attacker logs on
  to the target system using RDP and sends specially crafted data over the
  authenticated connection.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code with elevated privileges. Failed exploit
  attempts will result in a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012

  Microsoft Windows Server 2012 R2

  Microsoft Windows 10 x32/x64

  Microsoft Windows 7 x32/x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3134700");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_rdp_version_detect_win.nasl");
  script_mandatory_keys("remote/desktop/protocol/Win/Installed");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

RdpVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Rdpcorets.dll");
if(!RdpVer){
  exit(0);
}

mstsVer = get_app_version(cpe:CPE);

if(hotfix_check_sp(win7:2, win7x64:2) > 0)
{

  if(version_in_range(version:mstsVer, test_version:"6.2.9200.00000", test_version2:"6.2.9200.99999"))
  {
    if(version_is_less(version:RdpVer, test_version:"6.2.9200.17395"))
    {
      Vulnerable_range = "Less than 6.2.9200.17395";
      VULN = TRUE ;
    }
    else if(version_in_range(version:RdpVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21505"))
    {
      Vulnerable_range = "6.2.9200.21000 -6.2.9200.21505";
      VULN = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:RdpVer, test_version:"6.2.9200.17610"))
  {
    Vulnerable_range = "Less than 6.2.9200.17610";
    VULN = TRUE ;
  }
  else if(version_in_range(version:RdpVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21728"))
  {
    Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21728";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:RdpVer, test_version:"6.3.9600.18167"))
  {
    Vulnerable_range = "Less than 6.3.9600.18167";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:RdpVer, test_version:"10.0.10240.16683"))
  {
    Vulnerable_range = "Less than 10.0.10240.16603";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Rdpcorets.dll" + '\n' +
           'File version:     ' + RdpVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}