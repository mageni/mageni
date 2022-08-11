###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Hyper-V Multiple Vulnerabilities (4013082)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810624");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0021", "CVE-2017-0051", "CVE-2017-0074", "CVE-2017-0075",
                "CVE-2017-0076", "CVE-2017-0097", "CVE-2017-0099", "CVE-2017-0095",
                "CVE-2017-0096", "CVE-2017-0098", "CVE-2017-0109");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 10:50:15 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Windows Hyper-V Multiple Vulnerabilities (4013082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4013082");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-008");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-008.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - Microsoft Hyper-V Network Switch on a host server fails to properly validate
    input from a privileged user on a guest operating system.

  - Microsoft Hyper-V on a host server fails to properly validate vSMB packet
    data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial of service attack, execute arbitrary code on
  the target operating system and gain access to potentially sensitive
  information.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x64 Edition Service Pack 2

  Microsoft Windows 7 x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows 8.1 x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 x64

  Microsoft Windows 10 Version 1511 x64

  Microsoft Windows 10 Version 1607 x64

  Microsoft Windows Server 2016 x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVistax64:3, win2008x64:3, win7x64:2, win2008r2:2, win8_1x64:1,
                   win2012:1, win2012R2:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

vmmsexe = fetch_file_version(sysPath:sysPath, file_name:"VMMS.exe");
if(!vmssexe){
  exit(0);
}

hypVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\Vmswitch.sys");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll");
if(!hypVer && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(winVistax64:3, win2008x64:3) > 0 && hypVer)
{
  if(version_is_less(version:hypVer, test_version:"6.0.6002.24070"))
  {
    Vulnerable_range = "Less than 6.0.6002.24070";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0 && hypVer)
{
  ## GDR info not given
  if(version_is_less(version:hypVer, test_version:"6.1.7601.23677"))
  {
    Vulnerable_range = "Less than 6.1.7601.23677";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1x64:1, win2012R2:1) > 0 && hypVer)
{
  if(version_is_less(version:hypVer, test_version:"6.3.9600.18589"))
  {
    Vulnerable_range = "Less than 6.3.9600.18569";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && hypVer)
{
  if(version_is_less(version:hypVer, test_version:"6.2.9200.22086"))
  {
    Vulnerable_range = "Less than 6.2.9200.22086";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17319"))
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.839";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\drivers\Vmswitch.sys" + '\n' +
           'File version:     ' + hypVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
