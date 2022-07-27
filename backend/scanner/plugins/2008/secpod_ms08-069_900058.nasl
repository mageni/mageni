##############################################################################
# OpenVAS Vulnerability Test
# Description: Microsoft XML Core Services Remote Code Execution Vulnerability (955218)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900058");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-11-12 16:32:06 +0100 (Wed, 12 Nov 2008)");
  script_bugtraq_id(21872, 32204);
  script_cve_id("CVE-2007-0099", "CVE-2008-4029", "CVE-2008-4033");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft XML Core Services Remote Code Execution Vulnerability (955218)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-069.mspx");

  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to conduct cross domain
  scripting attacks and read data from another domain in IE and also execute
  arbitrary code by tricking a user into visiting a malicious web page.");

  script_tag(name:"affected", value:"Microsoft XML Core Services 3.0/4.0/5.0/6.0

  Microsoft Windows 2K Service Pack 4 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.

  Microsoft Office 2003 & 2007.

  Microsoft Office Compatibility Pack for Word/Excel/PowerPoint 2007 File Formats.");

  script_tag(name:"insight", value:"The flaws are due to,

  - a memory corruption error when parsing malformed XML content.

  - the way MSXML handles error checks for external document type definitions
    (DTDs).

  - an error in the way MSXML handles transfer-encoding headers.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-069.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

# Microsoft Office 2003 & 2007
if((officeVer && officeVer =~ "^1[12]\.")||
   registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  sharedPath = registry_get_sz(key:"SOFTWARE\Microsoft\Shared Tools", item:"SharedFilesDir");
  if(sharedPath)
  {
    share2 = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sharedPath);
    file5 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:sharedPath + "OFFICE11\msxml5.dll");
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
if(sysPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file6 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml6.dll");
  file6r = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml6r.dll");
  file4 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4.dll");
  file4a = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4a.dll");
  file4r = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4r.dll");
  file3 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml3.dll");

  if(!isnull(share) && !isnull(file6))
  {
    # MSXML6.dll < 6.20.1099.0
    if(egrep(pattern:"^([0-5]\..*|6\.([01]?[0-9]|20\.(0?[0-9]?[0-9]?[0-9]|10([0-8]" +
                 "[0-9]|9[0-8])))\..*)$",
         string:GetVer(file:file6, share:share)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML6r.dll < 6.0.3883.0
  if(!isnull(file6r) && !isnull(share))
  {
    if(egrep(pattern:"^([0-5]\..*|6\.(0\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-7]" +
                 "[0-9][0-9]|8[0-7][0-9]|88[0-2])))\..*)$",
         string:GetVer(file:file6r, share:share)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML5.dll < 5.20.1087.0
  if(!isnull(file5) && !isnull(share2))
  {
    if(egrep(pattern:"^([0-4]\..*|5\.([01]?[0-9]\..*|20\.([0-9]?[0-9]?[0-9]|10" +
                 "([0-7][0-9]|8[0-6]))\..*))$",
      string:GetVer(file:file5, share:share2)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML4.dll < 4.20.9870.0
  if(!isnull(file4) && !isnull(share))
  {
    if(egrep(pattern:"^([0-3]\..*|4\.([01]?[0-9]\..*|20\.([0-8]?[0-9]?[0-9]?[0-9]" +
                 "\..*|9([0-7][0-9][0-9]|8[0-6][0-9])\..*)))$",
      string:GetVer(file:file4, share:share)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML4A.dll < 4.10.9404.0
  if(!isnull(file4a) && !isnull(share))
  {
    if(egrep(pattern:"^([0-3]\..*|4\.([0-9]\..*|10\.([0-8]?[0-9]?[0-9]?[0-9]" +
                 "\..*|9([0-3][0-9][0-9]|40[0-3])\..*)))$",
         string:GetVer(file:file4a, share:share)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML4R.dll < 4.10.9404.0
  if(!isnull(file4r) && !isnull(share))
  {
    if(egrep(pattern:"^([0-3]\..*|4\.([0-9]\..*|10\.([0-8]?[0-9]?[0-9]?[0-9]" +
               "\..*|9([0-3][0-9][0-9]|40[0-3])\..*)))$",
        string:GetVer(file:file4r, share:share)))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  # MSXML3.dll < 8.100.1048.0
  if(!isnull(file3) && !isnull(share))
  {
    if(egrep(pattern:"^([0-7]\..*|8\.([0-9]?[0-9]\..*|100\.([0-9]?[0-9]?[0-9]" +
                 "\..*|1(0[0-3][0-9]|04[0-7])\..*)))$",
         string:GetVer(file:file3, share:share))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
      exit(0);
  }
}


sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml4.dll");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml6.dll");
if(dllVer || dllVer2 || dllVer3)
{
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.100.1047.9") ||
       version_in_range(version:dllVer2, test_version:"4.0", test_version2:"4.20.9869.9") ||
       version_in_range(version:dllVer3, test_version:"6.0", test_version2:"6.20.1098.9")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(hotfix_check_sp(win7:1) > 0)
  {
    if(version_in_range(version:dllVer2, test_version:"4.0", test_version2:"4.20.9869.9")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
