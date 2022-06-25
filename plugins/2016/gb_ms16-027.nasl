###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Media Remote Code Execution Vulnerabilities (3143146)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806897");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0098", "CVE-2016-0101");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-03-09 09:44:08 +0530 (Wed, 09 Mar 2016)");
  script_name("Microsoft Windows Media Remote Code Execution Vulnerabilities (3143146)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-027");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper
  handling of resources in the media library.");

  script_tag(name:"impact", value:"Successful exploitation will allow  an
  remote attacker to take control of an affected system remotely.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.
  Microsoft Windows 10 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3138962");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3138910");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-027");

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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Wmp.dll");
sysVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Mfds.dll");

if(!sysVer1 && !sysVer2){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(sysVer1)
  {
    if(version_is_less(version:sysVer1, test_version:"12.0.7601.19148"))
    {
      Vulnerable_range1 = "Less than 12.0.7601.19148";
      VULN1 = TRUE;
    }
    else if(version_in_range(version:sysVer1, test_version:"12.0.7601.23000", test_version2:"12.0.7601.23347"))
    {
      Vulnerable_range1 = "12.0.7601.23000 - 12.0.7601.23347";
      VULN1 = TRUE;
    }
  }

  if(sysVer2)
  {
    if(version_is_less(version:sysVer2, test_version:"12.0.7601.19145"))
    {
      Vulnerable_range2 = "Less than 12.0.7601.19145";
      VULN2 = TRUE;
    }
    else if(version_in_range(version:sysVer2, test_version:"12.0.7601.23000", test_version2:"12.0.7601.23345"))
    {
      Vulnerable_range2 = "12.0.7601.23000 - 12.0.7601.23345";
      VULN2 = TRUE;
    }
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(sysVer1 && version_is_less(version:sysVer1, test_version:"12.0.9600.18229"))
  {
    Vulnerable_range1 = "Less than 12.0.9600.18229";
    VULN1 = TRUE;
  }

  if(sysVer2 && version_is_less(version:sysVer2, test_version:"12.0.9600.18228"))
  {
    Vulnerable_range2 = "Less than 12.0.9600.18228";
    VULN2 = TRUE;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(sysVer1)
  {
    if(version_is_less(version:sysVer1, test_version:"12.0.9200.17648"))
    {
      Vulnerable_range1 = "Less than 12.0.9200.17648";
      VULN1 = TRUE;
    }
    else if(version_in_range(version:sysVer1, test_version:"12.0.9200.21000", test_version2:"12.0.9200.21766"))
    {
      Vulnerable_range1 = "12.0.9200.21000 - 12.0.9200.21766";
      VULN1 = TRUE;
    }
  }
  if(sysVer2)
  {
    if(version_is_less(version:sysVer2, test_version:"12.0.9200.17647"))
    {
      Vulnerable_range2 = "Less than 12.0.9200.17647";
      VULN2 = TRUE;
    }
    else if(version_in_range(version:sysVer2, test_version:"12.0.9200.21000", test_version2:"12.0.9200.21765"))
    {
      Vulnerable_range2 = "12.0.9200.21000 - 12.0.9200.21765";
      VULN2 = TRUE;
    }
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && sysVer1)
{
  if(version_is_less(version:sysVer1, test_version:"12.0.10240.16724"))
  {
    Vulnerable_range1 = "Less than 12.0.10240.16724";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:sysVer1, test_version:"12.0.10586.0", test_version2:"12.0.10586.161"))
  {
    Vulnerable_range1 = "12.0.10586.0 - 12.0.10586.161";
    VULN1 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\Wmp.dll" + '\n' +
           'File version:     ' + sysVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Mfds.dll" + '\n' +
           'File version:     ' + sysVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
