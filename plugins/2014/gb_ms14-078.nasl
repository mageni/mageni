###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows IME (Japanese) Privilege Elevation Vulnerability (2992719)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802088");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-4077");
  script_bugtraq_id(70944);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-11-12 13:07:08 +0530 (Wed, 12 Nov 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Windows IME (Japanese) Privilege Elevation Vulnerability (2992719)");

  script_tag(name:"summary", value:"This host is missing a moderate security
  update according to Microsoft Bulletin MS14-078.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Error in 'IMJPDCT.EXE', which allow
  remote attackers to bypass a sandbox protection mechanism via a crafted PDF
  document. Aka 'Microsoft IME (Japanese) Elevation of Privilege Vulnerability'
  as exploited in the wild in 2014.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to bypass a sandbox protection mechanism via a crafted PDF document.");

  script_tag(name:"affected", value:"Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2991963");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-078");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/srd/archive/2014/11/11/assessing-risk-for-the-november-2014-security-updates.aspx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3,
                   win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  key = "SOFTWARE\Microsoft\IMEJP\8.1";
  if(!registry_key_exists(key:key)){
    exit(0);
  }

  dllVer = fetch_file_version(sysPath:sysPath, file_name:"IME\IMJP8_1\Imjputyc.dll");
  if(!dllVer){
    exit(0);
  }

  if(version_is_less(version:dllVer, test_version:"8.1.7104.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }

  exit(0);
}

key = "SOFTWARE\Microsoft\IMEJP\10.0";
if(!registry_key_exists(key:key)){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\IME\IMEJP10\Imjputyc.dll");
if(!dllVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"10.0.6002.19154") ||
     version_in_range(version:dllVer, test_version:"10.0.6002.23000", test_version2:"10.0.6002.23458")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"10.1.7601.18556") ||
     version_in_range(version:dllVer, test_version:"10.1.7601.22000", test_version2:"10.1.7601.22763")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
