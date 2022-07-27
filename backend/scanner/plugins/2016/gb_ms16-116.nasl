###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft VBScript Scripting Engine OLE Automation Memory Corruption Vulnerability (3188724)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809040");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3375");
  script_bugtraq_id(92835);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 08:01:49 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft VBScript Scripting Engine OLE Automation Memory Corruption Vulnerability (3188724)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-116");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper way of accessing
  objects in the memory by Microsoft OLE Automation mechanism and the
  VBScript Scripting Engine in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code in the context of the current user.");

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

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3188724");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-116");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-116");
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

olePath = smb_get_systemroot();
if(!olePath){
  exit(0);
}

if(!oleVer = fetch_file_version(sysPath: olePath, file_name:"system32\Oleaut32.dll")){;
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.0.6002.19680"))
  {
    Vulnerable_range = "Less than 6.0.6002.19680";
    VULN = TRUE ;
  }
  else if(version_in_range(version:oleVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24006"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24006";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.1.7601.23512"))
  {
    Vulnerable_range = "Less than 6.1.7601.23512";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.2.9200.21950"))
  {
     Vulnerable_range = "Less than 6.2.9200.21950";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.3.9600.18434"))
  {
    Vulnerable_range = "Less than 6.3.9600.18434";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"10.0.10240.17113"))
  {
    Vulnerable_range = "Less than 10.0.10240.17113";
    VULN = TRUE ;
  }

  else if(version_in_range(version:oleVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.588"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.588";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + olePath + "\system32\Oleaut32.dll"+ '\n' +
           'File version:     ' + oleVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
