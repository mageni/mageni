###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft XML Core Services Remote Code Execution Vulnerabilities (2756145)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903101");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-0006", "CVE-2013-0007");
  script_bugtraq_id(57116, 57122);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-01-09 12:27:26 +0530 (Wed, 09 Jan 2013)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft XML Core Services Remote Code Execution Vulnerabilities (2756145)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS13-002.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Integer truncation and an unspecified error
  caused due to the way that Microsoft XML Core Services parses XML content.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote
  attackers to execute arbitrary code as the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Expression Web 2

  Microsoft Office Word Viewer

  Microsoft Office Compatibility

  Microsoft Office 2003 Service Pack 3 and prior

  Microsoft Office 2007 Service Pack 3 and prior

  Microsoft XML Core Services 3.0, 4.0, 5.0 and 6.0

  Microsoft Expression Web Service Pack 1 and prior

  Microsoft Groove Server 2007 Service Pack 3 and prior

  Microsoft SharePoint Server 2007 Service Pack 3 and prior

  Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51773/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80873");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80875");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2756145");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_groove_server_detect_win.nasl", "gb_ms_expression_web_detect.nasl",
                      "secpod_office_products_version_900032.nasl", "gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(! sysPath){
   exit(0);
}

dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3.dll");

if(dllVer3)
{
  if(hotfix_check_sp(xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.100.1053.0"))
    {
       Vulnerable_range = "Version Less than - 8.100.1053.0";
       VULN = TRUE ;
     }
  }
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.110.7600.17157")){
      Vulnerable_range = "Version Less than - 8.110.7600.17157";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7600.20000", test_version2:"8.110.7600.21359")){
      Vulnerable_range = "8.110.7600.20000 - 8.110.7600.21359";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.17000", test_version2:"8.110.7601.17987")){
      Vulnerable_range = "8.110.7601.17000 - 8.110.7601.17987";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.21000", test_version2:"8.110.7601.22148")){
      Vulnerable_range = "8.110.7601.21000 - 8.110.7601.22148";
      VULN = TRUE ;
    }
  }

  dllVer = dllVer3 ;
  location = sysPath + "\system32\Msxml3.dll";
}

dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml4.dll");

if(dllVer4)
{
  if(version_is_less(version:dllVer4, test_version:"4.30.2117.0"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Msxml4.dll" + '\n' +
             'File version:     ' + dllVer4  + '\n' +
             'Vulnerable range: Version Less than -  4.30.2117.0\n' ;
    security_message(data:report);
    exit(0);
  }
}

dllVer6 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml6.dll");
if(dllVer6)
{
  if(hotfix_check_sp(xp:4, win2003:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.2502.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.2502.0";
      VULN = TRUE ;
    }
  }

  ## Installed patch and took version
  else if(hotfix_check_sp(xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.2016.0"))
    {
      Vulnerable_range = "Version Less than -  6.20.2016.0";
      VULN = TRUE ;
    }
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.5006.0"))
    {
      Vulnerable_range = "Version Less than -  6.20.5006.0";
      VULN = TRUE ;
    }
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.30.7600.17157")){
      Vulnerable_range = "Version Less than - 6.30.7600.17157";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7600.20000", test_version2:"6.30.7600.21359")){
      Vulnerable_range = "6.30.7600.20000 - 6.30.7600.21359";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.17000", test_version2:"6.30.7601.17987")){
       Vulnerable_range = "6.30.7601.17000 - 6.30.7601.17987";
       VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.21000", test_version2:"6.30.7601.22148"))
    {
      Vulnerable_range = "6.30.7601.21000 - 6.30.7601.22148";
      VULN = TRUE ;
    }
  }

  dllVer = dllVer4 ;
  location = sysPath + "\system32\Msxml6.dll";
}

if(VULN)
{
  report = 'File checked:     ' + location + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");
wordVer = get_kb_item("SMB/Office/Word/Version");
wordCnvVer = get_kb_item("SMB/Office/WordCnv/Version");
grooveSrvVer = get_kb_item("MS/Groove-Server/Ver");
shrPtSrvVer = get_kb_item("MS/SharePoint/Server/Ver");
expressWebVer = get_kb_item("MS/Expression-Web/Ver");

## Groove server 2007 , Sharepoint Server 2007
if((officeVer && officeVer =~ "^1[12]\.") ||
    wordVer || wordCnvVer ||
    (grooveSrvVer && grooveSrvVer =~ "^12\.") ||
    (shrPtSrvVer && shrPtSrvVer =~ "^12\.") ||
    (expressWebVer && expressWebVer =~ "^12\."))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(! sysPath){
    exit(0);
  }

  foreach ver (make_list("OFFICE11", "OFFICE12"))
  {
    sysPath = sysPath + "\Microsoft Shared\" + ver ;

    dllVer5 = fetch_file_version(sysPath:sysPath, file_name:"Msxml5.dll");

    if(! dllVer5){
     continue;
    }

    ## Installed patch and took version
    if(version_is_less(version:dllVer5, test_version:"5.20.1099.0"))
    {
      report = 'File checked:     ' + sysPath + "\system32\Msxml5.dll" + '\n' +
           'File version:     ' + dllVer5  + '\n' +
           'Vulnerable range: Version Less than - 5.20.1099.0 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
