###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (3178467)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809041");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3346", "CVE-2016-3352", "CVE-2016-3368", "CVE-2016-3369");
  script_bugtraq_id(92846, 92852, 92847, 92850);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 08:01:49 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Windows Multiple Vulnerabilities (3178467)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-110");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An elevation of privilege vulnerability exists in the way that Windows
    enforces permissions if an attacker loads a specially crafted DLL.

  - An information disclosure vulnerability exists when Windows fails to properly
    validate NT LAN Manager (NTLM) Single Sign-On (SSO) requests during Microsoft
    Account (MSA) login sessions.

  - An improper handling of objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to run arbitrary code as a system administrator, to brute force a
  user's NTLM password hash and to cause denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64.

  Microsoft Windows 8.1 x32/x64 Edition.

  Microsoft Windows Server 2012/2012R2.

  Microsoft Windows 10 Version 1511 x32/x64.

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior.

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior.

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior.

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3178467");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-110");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-110");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, winVistax64:3, win2008x64:3,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

lsVer = fetch_file_version(sysPath:sysPath, file_name:"lsasrv.dll");
ntVer = fetch_file_version(sysPath:sysPath, file_name:"ntdsai.dll");
EdgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!lsVer && !ntVer && !EdgeVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && ntVer)
{
  if(version_is_less(version:ntVer, test_version:"6.0.6002.19686"))
  {
    Vulnerable_range = "Less than 6.0.6002.19686";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:ntVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24007"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24007";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && ntVer)
{
  if(version_is_less(version:ntVer, test_version:"6.1.7601.23535"))
  {
    Vulnerable_range = "Less than 6.1.7601.23535";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && ntVer)
{
  if(version_is_less(version:ntVer, test_version:"6.2.9200.21953"))
  {
     Vulnerable_range = "Less than 6.2.9200.21953";
     VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012R2:1) > 0 && ntVer)
{
  if(version_is_less(version:ntVer, test_version:"6.3.9600.18435"))
  {
    Vulnerable_range = "Less than 6.3.9600.18435";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  if(ntVer)
  {
    if(version_is_less(version:ntVer, test_version:"6.3.9600.18435"))
    {
      Vulnerable_range = "Less than 6.3.9600.18435";
      VULN1 = TRUE ;
    }
  }
  else if(lsVer)
  {
    if(version_is_less(version:lsVer, test_version:"6.3.9600.18454"))
    {
      Vulnerable_range = "Less than 6.3.9600.18454";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:EdgeVer, test_version:"11.0.10240.17113"))
  {
    Vulnerable_range = "Less than 11.0.10240.17113";
    VULN3 = TRUE ;
  }
  else if(version_in_range(version:EdgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.588"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.588";
    VULN3 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\ntdsai.dll" + '\n' +
           'File version:     ' + ntVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\lsasrv.dll" + '\n' +
           'File version:     ' + lsVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + EdgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

