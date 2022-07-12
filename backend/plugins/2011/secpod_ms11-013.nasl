###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Kerberos Privilege Escalation Vulnerabilities (2496930)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2011-03-17
# updated the affected software in description part.
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902288");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2011-0043", "CVE-2011-0091");
  script_bugtraq_id(46130, 46140);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Kerberos Privilege Escalation Vulnerabilities (2496930)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow authenticated attackers to obtain a token
  with elevated privileges on the affected system and allows a man-in-the-middle
  attacker to force a downgrade in Kerberos communication between a client and
  server.");
  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows XP Service Pack 3  and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error in  Kerberos implementation supporting weak hashing mechanisms
     such as CRC32.

  - An error in Kerberos that does not correctly enforce stronger default
     encryption standards.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS11-013.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2478971");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2478971");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0326");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-013.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, win7:2) <= 0){
  exit(0);
}

if((hotfix_missing(name:"2478971") == 0) || (hotfix_missing(name:"2425227") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Kerberos.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6059")){
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
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4806")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16722") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20860") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.10000", test_version2:"6.1.7601.17526") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.20000", test_version2:"6.1.7601.21623")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
