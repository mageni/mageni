###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Common Log File System Driver Elevation of Privilege Vulnerability (3193706)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809801");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0026", "CVE-2016-3332", "CVE-2016-3333", "CVE-2016-3334",
		"CVE-2016-3335", "CVE-2016-3338", "CVE-2016-3340", "CVE-2016-3342",
		"CVE-2016-3343", "CVE-2016-7184");
  script_bugtraq_id(93998, 94008, 94009, 94012, 94011, 94014, 94010, 94013, 94007, 94015);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-09 08:58:28 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Common Log File System Driver Elevation of Privilege Vulnerability (3193706)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-134.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to windows common log file
  system (CLFS) driver improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run processes in an elevated context.");

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

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3193706");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-134");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-0134");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

clfVer = fetch_file_version(sysPath:sysPath, file_name:"clfs.sys");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!clfVer && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:clfVer, test_version:"6.3.9600.18514"))
  {
    Vulnerable_range = "Less than 6.3.9600.18514";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:clfVer, test_version:"6.1.7601.23572"))
  {
    Vulnerable_range = "Less than 6.1.7601.23572";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:clfVer, test_version:"6.2.9200.22007"))
  {
    Vulnerable_range = "Less than 6.2.9200.22007";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:clfVer, test_version:"6.0.6002.19703"))
  {
    Vulnerable_range = "Less than 6.0.6002.19703";
    VULN = TRUE ;
  }
  else if(version_in_range(version:clfVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24025"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24025";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17184"))
  {
    Vulnerable_range1 = "Less than 11.0.10240.17184";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.671"))
  {
    Vulnerable_range1 = "11.0.10586.0 - 11.0.10586.671";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.446"))
  {
    Vulnerable_range1 = "11.0.14393.0 - 11.0.14393.446";
    VULN1 = TRUE ;
  }

  if(VULN1)
  {
    report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\clfs.sys" + '\n' +
           'File version:     ' + clfVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
