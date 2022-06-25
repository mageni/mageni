#############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Video Control Remote Code Execution Vulnerability (3195360)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809063");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0142");
  script_bugtraq_id(93378);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-12 08:50:54 +0530 (Wed, 12 Oct 2016)");
  script_name("Microsoft Video Control Remote Code Execution Vulnerability (3195360)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-122");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Video Control
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to run arbitrary code in the context of the current user and could
  take control of the affected system if the current user is logged on with
  administrative user rights.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 10 x32/x64

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3195360");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-122");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-122");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, winVistax64:3, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

vidPath = smb_get_system32root();
if(!vidPath ){
  exit(0);
}

vidVer = fetch_file_version(sysPath: vidPath, file_name:"msvidctl.dll");
edgVer = fetch_file_version(sysPath: vidPath, file_name:"edgehtml.dll");
if(!vidVer && !edgVer){
  exit(0);
}

if (vidVer =~ "^6\.5\.6002\.1"){
  Vulnerable_range = "Less than 6.5.6002.19689";
}
else if (vidVer =~ "^6\.5\.6002\.2"){
  Vulnerable_range = "6.5.6002.23000 - 6.5.6002.24013";
}
else if (vidVer =~ "^6\.5\.7601"){
  Vulnerable_range = "Less than 6.5.7601.23544";
}
else if (vidVer =~ "^6\.5\.9600\.1"){
  Vulnerable_range = "Less than 6.5.9600.18464";
}

if(hotfix_check_sp(winVista:3, winVistax64:3) > 0)
{
  if(version_is_less(version:vidVer, test_version:"6.5.6002.19689")||
     version_in_range(version:vidVer, test_version:"6.5.6002.23000", test_version2:"6.5.6002.24013")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2) > 0)
{
  ## Presently GDR information is not available.
  if(version_is_less(version:vidVer, test_version:"6.5.7601.23544")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:vidVer, test_version:"6.5.9600.18464")){
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:edgVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range1 = "Less than 11.0.10240.17146";
    VULN1 = TRUE ;
  }

  else if(version_in_range(version:edgVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range1 = "11.0.10586.0 - 11.0.10586.632";
    VULN1 = TRUE ;
  }

  else if(version_in_range(version:edgVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range1 = "11.0.14393.0 - 11.0.14393.320";
    VULN1 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + vidPath + "\msvidctl.dll" + '\n' +
           'File version:     ' + vidVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + vidPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

