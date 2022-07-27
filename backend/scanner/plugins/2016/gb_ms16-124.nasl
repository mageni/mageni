#############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Registry Multiple Vulnerabilities (3193227)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809440");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0070", "CVE-2016-0073", "CVE-2016-0075", "CVE-2016-0079");
  script_bugtraq_id(93354, 93355, 93356, 93357);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-12 08:40:20 +0530 (Wed, 12 Oct 2016)");
  script_name("Microsoft Windows Registry Multiple Vulnerabilities (3193227)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-124");

  script_tag(name:"vuldetect", value:"Gets the vulnerable file version and
  checks if the appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple elevation of privilege
  vulnerabilities exist in Microsoft Windows when a Windows kernel API
  improperly allows a user to access sensitive registry information.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to information not intended to be available to the user.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 x32/x64

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3193227");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-124");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-124");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, winVistax64:3, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

kerPath = smb_get_system32root();
if(!kerPath ){
  exit(0);
}

kerVer = fetch_file_version(sysPath: kerPath, file_name:"ntoskrnl.exe");
edgeVer = fetch_file_version(sysPath: kerPath, file_name:"edgehtml.dll");
if(!kerVer && !edgeVer){
  exit(0);
}

if (kerVer =~ "^6\.0\.6002\.1"){
  Vulnerable_range = "Less than 6.0.6002.19697";
}
else if (kerVer =~ "^6\.0\.6002\.2"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24019";
}
else if (kerVer =~ "^6\.1\.7601"){
  Vulnerable_range = "Less than 6.1.7601.23564";
}
else if (kerVer =~ "^6\.2\.9200"){
  Vulnerable_range = "Less than 6.2.9200.22001";
}
else if (kerVer =~ "^6\.3\.9600\.1"){
  Vulnerable_range = "Less than 6.3.9600.18505";
}
else if (kerVer =~ "^10\.0\.10240"){
  Vulnerable_range = "Less than 10.0.10240.17146";
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win2008:3) > 0)
{
  if(version_is_less(version:kerVer, test_version:"6.0.6002.19697")||
     version_in_range(version:kerVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24019")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Presently GDR information is not available.
  if(version_is_less(version:kerVer, test_version:"6.1.7601.23564")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Presently GDR information is not available.
  if(version_is_less(version:kerVer, test_version:"6.2.9200.22001")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:kerVer, test_version:"6.3.9600.18505")){
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:kerVer, test_version:"10.0.10240.17146"))
  {
    Vulnerable_range = "Less than 10.0.10240.17146";
    VULN = TRUE ;
  }

  else if(edgeVer)
  {
    if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
    {
      Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.632";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
    {
      Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.320";
      VULN2 = TRUE ;
    }
  }
}

if(VULN)
{
  report = 'File checked:     ' + kerPath + "\\ntoskrnl.exe" + '\n' +
           'File version:     ' + kerVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + kerPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
