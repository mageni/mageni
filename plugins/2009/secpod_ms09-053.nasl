###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IIS FTP Service Remote Code Execution Vulnerabilities (975254)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-25
#      - To detect file version 'ftpsvc2.dll' on vista and win 2008
#
# Updated Updated By: Antu Sanadi <santu@secpod.com> on 2012-06-05
# - Updated to support GDR and LDR versions.
# - Removed get_file_version function.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900874");
  script_version("2019-05-03T08:55:39+0000");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2521", "CVE-2009-3023");
  script_bugtraq_id(36273, 36189);
  script_name("Microsoft IIS FTP Service Remote Code Execution Vulnerabilities (975254)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/975254");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2542");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2481");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-053");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code with
  SYSTEM privileges which may result Denial of Service on the affected server.");

  script_tag(name:"affected", value:"Microsoft Internet Information Server (IIS) 5.0/5/1/6.0.");

  script_tag(name:"insight", value:"- This issue is caused by an error when processing directory listing commands
  including the '*' character and '../' sequences, which could be exploited to exhaust the stack.

  - An heap-based buffer overflow error occurs in the FTP service when processing
  a specially crafted 'NLST' command.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-053.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-053 Hotfix check
if((hotfix_missing(name:"975254") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\ftpsvc2.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.0.2195.7336"))
  {
    security_message(21);
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.2600.3624")){
      security_message(21);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.2600.5875")){
     security_message(21);
    }
    exit(0);
  }
  security_message(21);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.3790.4584")){
      security_message(21);
    }
    exit(0);
  }
  security_message(21);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16922") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21122"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }

  SP = get_kb_item("SMB/WinVista/ServicePack");
  if(!SP){
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0.6001.18000", test_version2:"7.0.6001.18326") ||
       version_in_range(version:dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22515"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18106") ||
       version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22218"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
