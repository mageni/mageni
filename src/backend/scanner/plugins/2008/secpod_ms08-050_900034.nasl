##############################################################################
# OpenVAS Vulnerability Test
# Description: Windows Messenger Could Allow Information Disclosure Vulnerability (955702
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
  script_oid("1.3.6.1.4.1.25623.1.0.900034");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_bugtraq_id(30551);
  script_cve_id("CVE-2008-0082");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Windows Messenger Could Allow Information Disclosure Vulnerability (955702)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-050.mspx");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
 Microsoft Bulletin MS08-050.");
  script_tag(name:"insight", value:"Issue is in the Messenger.UIAutomation.1 ActiveX control being marked
        safe-for-scripting, which allows changing state, obtain contact information
        and a user's login ID.");
  script_tag(name:"affected", value:"Windows Messenger 4.7 on MS Windows 2K/XP
        Windows Messenger 5.1 on MS Windows 2K/XP/2003");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"impact", value:"Remote attackers can log on to a user's Messenger client as a user,
        and can initiate audio and video chat sessions without user interaction.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");
 include("secpod_smb_func.inc");
 include("version_func.inc");

 if(hotfix_check_sp(xp:3, win2k:5, win2003:3) <= 0){
	 exit(0);
 }

 dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components" +
                               "\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
                           item:"KeyFileName");

 dllPath = dllPath - "msmsgs.exe" + "msgsc.dll";


 if(!registry_key_exists(key:"SOFTWARE\Clients\IM\Windows Messenger")){
	exit(0);
 }

 msngrVer = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components" +
		                "\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
		  	    item:"Version");
 if(!msngrVer){
	exit(0);
 }

 if("5.1" >< msngrVer)
 {
	if(hotfix_missing(name:"899283") == 0){
                exit(0);
        }

	vers = get_version(dllPath:dllPath, offs:60000);
        if(vers == NULL){
                exit(0);
        }

	# Grep < 5.1.0715
        if(ereg(pattern:"^5\.1\.0?([0-6]?[0-9]?[0-9]|70[0-9]|71[0-4])0?$", string:vers)){
                security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
        exit(0);
 }

 else if("4,7" >< msngrVer)
 {
 	if(hotfix_check_sp(xp:4) > 0)
 	{
		if(hotfix_missing(name:"946648") == 0){
                	exit(0);
        	}
	}

	else if(hotfix_check_sp(win2003:3) > 0)
	{
		if(hotfix_missing(name:"954723") == 0){
                        exit(0);
                }
	}

        vers = get_version(dllPath:dllPath, offs:60000);
        if(vers == NULL){
               	exit(0);
        }

	# Grep < 4.7.3002
	if(ereg(pattern:"^4\.7\.([0-2]?[0-9]?[0-9]?[0-9]|300[01])0?$", string:vers)){
               	security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
 }