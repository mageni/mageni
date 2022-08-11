###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Active Directory Federation Services Information Disclosure Vulnerability (2873872)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802058");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3185");
  script_bugtraq_id(61672);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-08-14 15:33:05 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Active Directory Federation Services Information Disclosure Vulnerability (2873872)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  Bulletin MS13-066.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaw is due to an error within the Active Directory Federation
  Services (ADFS)");

  script_tag(name:"affected", value:"Active Directory Federation Services 2.1

  - Microsoft Windows Server 2012

  Active Directory Federation Services 2.0

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Active Directory Federation Services 1.0

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially sensitive information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54459");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2868846");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2843639");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2843638");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-066");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, win2008:3, win2008r2:2,
                   win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

adfs1 = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS");
adfs2 = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS2.0");

## Didn't find download for ADFS 2.1 So added with assumption
adfs3 = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS2.1");
if(!adfs1 && !adfs2 && !adfs3){
  exit(0);
}

if(adfs1){
  adfs1file_ver = fetch_file_version(sysPath:sysPath, file_name:"\ADFS\bin\ref\System.web.security.singlesignon.dll");
}

if(adfs2 || adfs3){
  adfs2file_ver = fetch_file_version(sysPath:sysPath, file_name:"\ADFS\Microsoft.identityserver.dll");
}

if(!adfs1file_ver && !adfs2file_ver){
  exit(0);
}

## Ignored KB2843638 as KB2843639 will apply both according to MS Bulletin
## i.e The 2843639 update is a roll-up of two updates (2843639 and 2843638)
## that are chain installed one after the other. Update 2843639 is installed
## first, followed by update 2843638. When the installations are complete,
## customers will see both updates 2843639 and 2843638 in the list of installed updates.

## But after applying the patch fileversion got upgrdaded to KB2843639 which
## is having higher file version then KB2843638
## Might create FP in some cases due to above check

## Bullein released
## With the rerelease of the AD FS 2.0 updates for Windows
## Server 2008 and Windows Server 2008 R2, the fixes contained in the two
## original updates (2843638 and 2843639) have been consolidated into a single
## update (2843638). When the installation is complete, customers will see only
## the 2843638 update in the list of installed updates. See the Update FAQ for details.


if(hotfix_check_sp(win2003:3, win2003x64:3) > 0 && adfs1file_ver)
{
  if(version_in_range(version:adfs1file_ver, test_version:"5.2.3790.0000", test_version2:"5.2.3790.5189")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  if(adfs1file_ver)
  {
    if(version_in_range(version:adfs1file_ver, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18879")||
       version_in_range(version:adfs1file_ver, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23151")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(adfs2file_ver)
  {
    if(version_in_range(version:adfs2file_ver, test_version:"6.1.7600.17000", test_version2:"6.1.7600.17337")||
       version_in_range(version:adfs2file_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22370")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win2008r2:2) > 0)
{
  if(adfs1file_ver)
  {
    if(version_in_range(version:adfs1file_ver, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18198")||
       version_in_range(version:adfs1file_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22374")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  if(adfs2file_ver)
  {
    if(version_in_range(version:adfs2file_ver, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18234")||
       version_in_range(version:adfs2file_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22419")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

else if(hotfix_check_sp(win2012:1) > 0 && adfs2file_ver)
{
  if(version_in_range(version:adfs2file_ver, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16650")||
     version_in_range(version:adfs2file_ver, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20759")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
