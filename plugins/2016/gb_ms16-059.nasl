###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Media Center Remote Code Execution Vulnerability (3150220)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807690");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-0185");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-05-11 08:11:30 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Media Center Remote Code Execution Vulnerability (3150220)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-059.");

  script_tag(name:"vuldetect", value:"Gets the vulnerable file version and checks if the
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error
  in the Windows Media Center which does not sanitize the input passed
  via the crafted Media Center link (.mcl) file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in user.
  Failed exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"Windows Media Center for

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 8.1 x32/x64 Edition

  - Microsoft Windows server 2008 and server 2008 R2

  - Microsoft Windows server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3150220");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-059");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win8_1:1, win8_1x64:1, winVista:3,
                   win2012:1, win2012R2:1, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

mcPath = smb_get_systemroot();
if(!mcPath){
  exit(0);
}

media_center_ver = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\Current" +
                                       "Version\Media Center", item:"Ident");

if(!media_center_ver){
  exit(0);
}

ehshell_ver = fetch_file_version(sysPath:mcPath, file_name:"ehome\Ehshell.dll");
if(!ehshell_ver){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## after patch GDR version also upgrading to LDR version
  if(version_is_less(version:ehshell_ver, test_version:"6.1.7601.23434"))
  {
    Vulnerable_range = "Less than 6.1.7601.23434";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:ehshell_ver, test_version:"6.3.9600.18299"))
  {
    Vulnerable_range = "Less Than 6.3.9600.18299";
    VULN = TRUE ;
  }
}

## Currently not supporting for Vista 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:ehshell_ver, test_version:"6.0.6002.19634"))
  {
    Vulnerable_range = "Less Than 6.0.6002.19634";
    VULN = TRUE ;
  }
  else if (version_in_range(version:ehshell_ver, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23947"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23947";
    VULN = TRUE ;
  }
}


if(VULN)
{
  report = 'File checked:     ' + mcPath + "\ehome\Ehshell.dll" + '\n' +
           'File version:     ' + ehshell_ver  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
