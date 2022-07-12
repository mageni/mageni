###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (2424434)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2011-07-18
#   - Updated Movie Maker path
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
  script_oid("1.3.6.1.4.1.25623.1.0.900266");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_bugtraq_id(42659);
  script_cve_id("CVE-2010-3967");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (2424434)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2424434");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-093.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to load crafted DLL
  file and execute any code it contained.");
  script_tag(name:"affected", value:"Movie Maker 2.6 on Microsoft Windows Vista Service Pack 1/2 and prior.");
  script_tag(name:"insight", value:"The flaw is due to Windows Movie Maker incorrectly restricting the path
  used for loading external libraries.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-093.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

## MS10-093 Hotfix check
if(hotfix_missing(name:"2424434") == 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\App Paths\moviemk.exe")){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
if(!sysPath){
  exit(0);
}

## Movie Maker path
moviemkPath = sysPath + "\Movie Maker\moviemk.exe";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:moviemkPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:moviemkPath);

moviemkVer = GetVer(file:file, share:share);
if(!moviemkVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP || "Service Pack 2" >< SP)
  {
    if(version_in_range(version: moviemkVer, test_version: "2.6", test_version2: "2.6.4039.9")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
