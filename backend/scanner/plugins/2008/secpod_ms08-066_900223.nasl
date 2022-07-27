##############################################################################
# OpenVAS Vulnerability Test
# Description: Microsoft Ancillary Function Driver Elevation of Privilege Vulnerability (956803)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900223");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31673);
  script_cve_id("CVE-2008-3464");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft Ancillary Function Driver Elevation of Privilege Vulnerability (956803)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS08-066.mspx");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to run arbitrary
  code in kernel mode with elevated privileges and take complete control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows Server 2003 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to the Ancillary Function Driver (afd.sys) not properly
  checking user supplied memory ranges before writing to them into location.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS08-066.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

sysFile = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
if(!sysFile){
  exit(0);
}

if(hotfix_missing(name:"956803") == 0){
  exit(0);
}

sysFile += "\drivers\Afd.sys";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysFile);

fileVer = GetVer(file:file, share:share);
if(fileVer == NULL){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(egrep(pattern:"^5\.1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9]" +
                     "[0-9]|4([01][0-9]|2[0-6])))$", string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(egrep(pattern:"^5\.1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9]" +
                     "[0-9]|6([0-4][0-9]|5[0-6])))$", string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(egrep(pattern:"^5\.2\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3(0[0-9][0-9]" +
                     "|1([0-8][0-9]|9[01])))$", string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else if("Service Pack 2" >< SP)
  {
    if(egrep(pattern:"^5\.2\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9]" +
                     "[0-9]|3([0-4][0-9]|5[0-4])))$", string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
