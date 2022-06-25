###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows License Logging Server Remote Code Execution Vulnerability (974783)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901047");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2523");
  script_bugtraq_id(36921);
  script_name("MS Windows License Logging Server Remote Code Execution Vulnerability (974783)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/974783");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3190");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-064.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  Service or execute arbitrary code on the victim's system.");
  script_tag(name:"affected", value:"Microsoft Windows 2K  Service Pack 4 and prior.");
  script_tag(name:"insight", value:"This issue is caused by a buffer overflow error in 'Llssrv.exe' when handling
  specially crafted RPC packets.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-064.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services"+
                                            "\LicenseService")){
 exit(0);
}

# MS09-064 Hotfix check
if(hotfix_missing(name:"974783") == 0){
  exit(0);
}

exePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                         item:"Install Path");
if(!exePath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:exePath +
                                                           "\Llssrv.exe");
exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"5.0.2195.7337")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
