###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2360131)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901162");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3331", "CVE-2010-3330", "CVE-2010-3329", "CVE-2010-3328",
                "CVE-2010-3327", "CVE-2010-3326", "CVE-2010-3325", "CVE-2010-3243",
                "CVE-2010-3324", "CVE-2010-0808");
  script_bugtraq_id(43695, 43703, 42467, 42993, 43696, 43704, 43705, 43706, 43709, 43707);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2360131)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2360131");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2618");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-071.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain knowledge of
  sensitive information or execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x");
  script_tag(name:"insight", value:"- The browser allowing for automated, scripted instructions to simulate user
    actions on the AutoComplete feature, which could allow attackers to capture
    information previously entered into fields after the AutoComplete feature
    has been enabled.

  - An error in the way the toStaticHTML API sanitizes HTML, which could allow
    cross-site scripting attacks.

  - An error when processing CSS special characters, which could allow attackers
    to view content from another domain or Internet Explorer zone.

  - An uninitialized memory corruption error when processing malformed data,
    which could allow attackers to execute arbitrary code via a malicious web page.

  - The Anchor element not being removed from the editable HTML element during
    specific user operations, potentially revealing personally identifiable
    information intended for deletion.

  - The browser allowing scripts to access and read content from different domains,
    which could allow cross-domain scripting attacks.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-071.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-071.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

## MS10-071 Hotfix (2360131)
if(hotfix_missing(name:"2360131") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\Iepeers.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2900.6035") ||
       version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6000.17090")||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18967")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.3790.4771") ||
       version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6000.17090")||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18967")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:2, win2008:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18526")||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18974")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6002.18308")||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18974")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.7600.16670")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
