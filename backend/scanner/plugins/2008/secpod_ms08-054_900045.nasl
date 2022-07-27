##############################################################################
# OpenVAS Vulnerability Test
# Description: Windows Media Player 11 Remote Code Execution Vulnerability (954154)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900045");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_bugtraq_id(30550);
  script_cve_id("CVE-2008-2253");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Windows Media Player 11 Remote Code Execution Vulnerability (954154)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-054.mspx");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
 Microsoft Bulletin MS08-054.");
  script_tag(name:"insight", value:"The flaw is due to an error when handling sampling rates
	in Windows Media Player.");
  script_tag(name:"affected", value:"Windows Media Player 11 on Windows XP");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"impact", value:"Remote attackers can exploit via specially crafted audio
        file stream from a server side playlist (SSPL) that could allow
        arbitrary code execution when streamed from windows media server.
        This allow attacker to compromise a user's system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");
 include("version_func.inc");
 include("secpod_smb_func.inc");

 if(hotfix_check_sp(xp:4, winVista:4) <= 0){
	 exit(0);
 }

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\wmpeffects.dll";
if(!registry_key_exists(key:"SOFTWARE\Microsoft\MediaPlayer")){
	exit(0);
}

mplayerVer = registry_get_sz(key:"SOFTWARE\Microsoft\Active setup\Installed Components" +
				  "\{6BF52A52-394A-11d3-B153-00C04F79FAA6}",
			     item:"Version");

if("11,0,5721" >< mplayerVer)
{
	if(hotfix_missing(name:"954154") == 0){
                exit(0);
        }

	vers = get_version(dllPath:dllPath);
        if(vers == NULL){
                exit(0);
        }

	# Grep Wmpeffects.dll version < 11.0.5721.5252
        if(ereg(pattern:"^11\.0\.5721\.([0-4]?[0-9]?[0-9]?[0-9]|5[01][0-9][0-9]" +
			"|52[0-4][0-9]|525[01])$", string:vers)){
                security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
 }

if(hotfix_missing(name:"954154") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Wmpeffects.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7001")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
         exit(0);
  }
}

else if(hotfix_check_sp(win2008:2) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7001")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
      exit(0);
  }
}
