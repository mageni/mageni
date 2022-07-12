###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Netlogon Remote Code Execution Vulnerability (3167691)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808227");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3228");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-15 08:30:23 +0530 (Wed, 15 Jun 2016)");
  script_name("Microsoft Windows Netlogon Remote Code Execution Vulnerability (3167691)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-076.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw occurs when windows improperly
  handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the currently logged-in user.
  Failed exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012/2012R2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3167691");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-076");

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

if(hotfix_check_sp(win2008:3, win2008r2:2, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

wgdllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Wdigest.dll");
cngsysVer = fetch_file_version(sysPath:sysPath, file_name:"System32\drivers\Cng.sys");
if(!wgdllVer && !cngsysVer){
  exit(0);
}

if(hotfix_check_sp(win2008:3) > 0 && wgdllVer)
{
  if(version_is_less(version:wgdllVer, test_version:"6.0.6002.19659"))
  {
    Vulnerable_range = "Less than 6.0.6002.19659";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:wgdllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23973"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23973";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win2008r2:2) > 0 && cngsysVer)
{
  if(version_is_less(version:cngsysVer, test_version:"6.1.7601.23451"))
  {
    Vulnerable_range = "Less than 6.1.7601.23451";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && cngsysVer)
{
  if(version_is_less(version:cngsysVer, test_version:"6.2.9200.21637"))
  {
     Vulnerable_range = "Less than 6.2.9200.21637";
     VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012R2:1) > 0 && cngsysVer)
{
  if(version_is_less(version:cngsysVer, test_version:"6.3.9600.18340"))
  {
    Vulnerable_range = "Less than 6.3.9600.18340";
    VULN1 = TRUE ;
  }
}

## Server 2012 R2
else if(hotfix_check_sp(win2012R2:1) > 0 && wgdllVer)
{
  if(version_is_less(version:wgdllVer, test_version:"6.3.9600.18334"))
  {
    Vulnerable_range = "Less than 6.3.9600.18334";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\drivers\cng.sys" + '\n' +
           'File version:     ' + cngsysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Wdigest.dll" + '\n' +
           'File version:     ' + wgdllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

