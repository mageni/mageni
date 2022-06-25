##############################################################################
# OpenVAS Vulnerability Test
# Description: Cumulative Security Update for Internet Explorer (953838)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900030");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_bugtraq_id(30610, 30611, 30612, 30613, 30614);
  script_cve_id("CVE-2008-2254", "CVE-2008-2255", "CVE-2008-2256",
	       "CVE-2008-2257", "CVE-2008-2258", "CVE-2008-2259");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Cumulative Security Update for Internet Explorer (953838)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-045.mspx");
  script_tag(name:"summary", value:"This host is missing critical security update according to
 Microsoft Bulletin MS08-045.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - uninitialized memory in certain situations.

  - an object that has not been correctly initialized or that has been deleted.

  - the way it handles argument validation in print preview handling.");
  script_tag(name:"affected", value:"MS Internet Explorer 5.01 & 6 on MS Windows 2000
	MS Internet Explorer 6 on MS Windows 2003 and XP
        MS Internet Explorer 7 on MS Windows 2003 and XP
        MS Internet Explorer 7 on MS Windows 2008 and Vista");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"impact", value:"Remote attackers could execute remote code on the vulnerable
        system to gain the same user rights as the logged-on user.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");
 include("version_func.inc");
 include("secpod_smb_func.inc");
 include("secpod_ie_supersede.inc");

 if(hotfix_check_sp(xp:4, win2k:5, win2003:3, win2008:2, winVista:2) <= 0){
        exit(0);
 }

 if(hotfix_missing(name:"953838") == 0){
              exit(0);
 }

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\mshtml.dll";

 ieVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer",
                         item:"Version");
 if(!ieVer){
     ieVer = registry_get_sz(item:"IE",
		      key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
 }

 if(!ieVer){
	exit(0);
 }

 if(ie_latest_hotfix_update(bulletin:"MS08-045")){
   exit(0);
 }

 if(hotfix_check_sp(win2k:5) > 0)
 {
        vers = get_version(dllPath:dllPath, string:"prod", offs:2000000);
        if(vers == NULL){
                exit(0);
        }

        if(ereg(pattern:"^5\..*", string:ieVer))
        {
		# Grep < 5.0.3866.2000
                if(ereg(pattern:"^(5\.00\.(([0-2]?[0-9]?[0-9]?[0-9]|3?([0-7]?"+
                                "[0-9]?[0-9]|8?([0-5]?[0-9]|6[0-5])))(\..*)|"+
                                "3866\.[01]?[0-9]?[0-9]?[0-9]))$", string:vers)){
                        security_message( port: 0, data: "The target host was found to be vulnerable" );
                }
                exit(0);
        }

        if(ereg(pattern:"^6\..*", string:ieVer))
        {
		# Grep < 6.0.2800.1614
                if(ereg(pattern:"^(6\.00\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-7]?["+
                                "0-9]?[0-9]))(\..*)|2800\.(0?[0-9]?[0-9]?[0-"+
                                "9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-3])))))$",
                        string:vers)){
                        security_message( port: 0, data: "The target host was found to be vulnerable" );
                }
                exit(0);
        }
 }

 if(hotfix_check_sp(xp:4) > 0)
 {
        vers = get_version(dllPath:dllPath, string:"prod", offs:2000000);
        if(vers == NULL){
                exit(0);
        }

	SP = get_kb_item("SMB/WinXP/ServicePack");
        if(ereg(pattern:"^6\..*", string:ieVer))
        {
                if("Service Pack 2" >< SP)
                {
			# Grep < 6.0.2900.3395
			if(ereg(pattern:"^(6\.00\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-8]?["+
                                "0-9]?[0-9]))(\..*)|2900\.([0-2]?[0-9]?[0-9]"+
                                "?[0-9]|3([0-2][0-9][0-9]|3([0-8][0-9]"+
                                "|9[0-4])))))$", string:vers)){
 				security_message( port: 0, data: "The target host was found to be vulnerable" );
                	}
                	exit(0);
        	}
		if("Service Pack 3" >< SP)
		{
			# Grep < 6.0.2900.5626
			if(ereg(pattern:"^(6\.00\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-8]?["+
                                "0-9]?[0-9]))(\..*)|2900\.([0-4]?[0-9]?[0-9]"+
                                "?[0-9]|5([0-5][0-9][0-9]|6([01][0-9]"+
                                "|2[0-5])))))$", string:vers)){
                                security_message( port: 0, data: "The target host was found to be vulnerable" );
                        }
                        exit(0);
		}
		else security_message( port: 0, data: "The target host was found to be vulnerable" );
	}

        if(ereg(pattern:"^7\..*", string:ieVer))
        {
		# Grep < 7.0.6000.16705
                if(ereg(pattern:"^(7\.00\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\."+
                                "(0?[0-9]?[0-9]?[0-9]?[0-9]|1([0-5][0-9]"+
                                "[0-9][0-9]|6([0-6][0-9][0-9]|70[0-4])))))$",
			string:vers)){
                        security_message( port: 0, data: "The target host was found to be vulnerable" );
                }
                exit(0);
        }
 }

 if(hotfix_check_sp(win2003:3) > 0)
 {
        vers = get_version(dllPath:dllPath, string:"prod", offs:2000000);
        if(vers == NULL){
                exit(0);
        }

	SP = get_kb_item("SMB/Win2003/ServicePack");
        if(ereg(pattern:"^6\..*", string:ieVer))
        {
		if("Service Pack 1" >< SP)
                {
			# Grep < 6.0.3790.3167
			if(ereg(pattern:"(6\.00\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6]"+
                                "[0-9][0-9]|7[0-8][0-9]))(\..*)|3790\.([0"+
                                "-2]?[0-9]?[0-9]?[0-9]|3(0[0-9][0-9]|1(["+
                                "0-5]?[0-9]|6?[0-6])))))$", string:vers)){
            			security_message( port: 0, data: "The target host was found to be vulnerable" );
                	}
                	exit(0);
        	}

		if("Service Pack 2" >< SP)
		{
			# Grep < 6.0.3790.4324
                        if(ereg(pattern:"(6\.00\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6]"+
                                "[0-9][0-9]|7[0-8][0-9]))(\..*)|3790\.([0"+
                                "-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|3(["+
                                "01]?[0-9]|2[0-3])))))$", string:vers)){
                                security_message( port: 0, data: "The target host was found to be vulnerable" );
                        }
                        exit(0);
                }
		else security_message( port: 0, data: "The target host was found to be vulnerable" );
	}

        if(ereg(pattern:"^7\..*", string:ieVer))
        {
		# Grep < 7.0.6000.16705
                if(ereg(pattern:"(7\.00\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\."+
                                "(0?[0-9]?[0-9]?[0-9]?[0-9]|1([0-5][0-9]"+
                                "[0-9][0-9]|6([0-6][0-9][0-9]|70[0-4])))))$",
			string:vers)){
                        security_message(get_kb_item("SMB/transport"));
                }
                exit(0);
        }
 }

 dllPath = smb_get_system32root();
 if(!dllPath){
   exit(0);
 }

 dllVer =  fetch_file_version(sysPath:dllPath, file_name:"\mshtml.dll");
 if(dllVer)
 {
   if(hotfix_check_sp(winVista:2) > 0)
   {
     SP = get_kb_item("SMB/WinVista/ServicePack");
     if("Service Pack 1" >< SP)
     {
       if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18098")){
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
       if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18098")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
         exit(0);
     }
   }
 }
