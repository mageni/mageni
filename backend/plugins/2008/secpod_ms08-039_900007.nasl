##############################################################################
# OpenVAS Vulnerability Test
# Description: Outlook Web Access for Exchange Server Elevation of Privilege (953747)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900007");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_bugtraq_id(30130);
  script_cve_id("CVE-2008-2247", "CVE-2008-2248");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Outlook Web Access for Exchange Server Elevation of Privilege (953747)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/43328");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Jul/1020439.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-039.mspx");
  script_tag(name:"summary", value:"This host is missing critical security update according to
 Microsoft Bulletin MS08-039.");
  script_tag(name:"insight", value:"The flaws are due to insufficient validation of certain e-mail fields
        and HTML in e-mail messages.");
  script_tag(name:"affected", value:"Microsoft Exchange Server (2003 and 2007) on Windows (2K and 2003).");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"impact", value:"Successful execution of exploit leads to arbitrary HTML and
        acript code execution in a user's browser session in the context of
        affected system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");

 if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
        exit(0);
 }

 function Get_FileVersion()
 {
	excFile = registry_get_sz(key:"SOFTWARE\Microsoft\Exchange\Setup",
                                  item:"MsiInstallPath");

	if(!excFile){
		exit(0);
	}

	excFile += "\bin\Davex.dll";
	share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:excFile);
 	file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:excFile);

        name    =  kb_smb_name();
        login   =  kb_smb_login();
        pass    =  kb_smb_password();
        domain  =  kb_smb_domain();
        port    =  kb_smb_transport();

        soc = open_sock_tcp(port);
        if(!soc){
                exit(0);
        }

        r = smb_session_request(soc:soc, remote:name);
        if(!r)
        {
                close(soc);
                exit(0);
        }

        prot = smb_neg_prot(soc:soc);
        if(!prot)
        {
                close(soc);
                exit(0);
        }

        r = smb_session_setup(soc:soc, login:login, password:pass,
                              domain:domain, prot:prot);
        if(!r)
        {
                close(soc);
                exit(0);
        }

        uid = session_extract_uid(reply:r);
        if(!uid)
        {
                close(soc);
                exit(0);
        }

        r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
        if(!r)
        {
                close(soc);
                exit(0);
        }

        tid = tconx_extract_tid(reply:r);
        if(!tid)
        {
                close(soc);
                exit(0);
        }

        fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
        if(!fid)
        {
                close(soc);
                exit(0);
        }

 	fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 	off = fsize - 90000;

 	while(fsize != off)
 	{
        	data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
        	data = str_replace(find:raw_string(0), replace:"", string:data);
        	version = strstr(data, "ProductVersion");
        	if(!version){
                	off += 16383;
        	}
        	else break;
 	}

 	if(!version){
        	exit(0);
 	}

	v = "";
 	for(i = strlen("ProductVersion"); i < strlen(version); i++)
 	{
        	if((ord(version[i]) < ord("0") ||
            	    ord(version[i]) > ord("9")) && version[i] != "."){
                	break;
        	}
        	else
                	v += version[i];
 	}
	return (v);
 }


 appName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
			       "\Uninstall\Microsoft Exchange",
                           item:"DisplayName");
 if(!appName){
	exit(0);
 }

 if("Microsoft Exchange Server 2003" >< appName)
 {
	if(hotfix_missing(name:"950159") == 0){
        	exit(0);
        }

	fileVer = Get_FileVersion();
        if(!fileVer){
		exit(0);
        }

	# Check for version < 6.5.7653.38
        if(egrep(pattern:"^(0?([0-5]\..*|6\.0?([0-4]\..*|5\.([0-6]?[0-9]?" +
			 "[0-9]?[0-9]\..*|7[0-5][0-9][0-9]\..*|76[0-4].*|765" +
			 "[0-2]\..*|7653\.0?([0-2]?[0-9]|3[0-7])))))$",
		 string:fileVer)){
       		security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
 }

 else if("Microsoft Exchange Server 2007" >< appName)
 {
	# Check for Service Pack in Exchange Server 2007
	spCheck = registry_get_dword(key:"SOFTWARE\Microsoft\Exchange\Setup",
			             item:"MsiProductMinor");
	if(!spCheck)
	{

 		if(hotfix_missing(name:"953469") == 0){
			exit(0);
 		}

		fileVer = Get_FileVersion();
 		if(!fileVer){
			exit(0);
 		}

		# Check for version < 8.0.750.0  08.00.0750.00
		if(egrep(pattern:"^(0?([0-7]\..*|8\.0?0\.0?([0-6]?[0-9][0-9]" +
				 "\..*|7[0-4][0-9]\..*)))$", string:fileVer)){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit(0);
	}

	else
	{
		if(hotfix_missing(name:"949870") == 0){
                        exit(0);
                }

		fileVer = Get_FileVersion();
                if(!fileVer){
                        exit(0);
                }

		# Check for version < 8.1.278.0
                if(egrep(pattern:"^(0?([0-7]\..*|8\.0?0\..*|8\.0?1\.0?([01]?[0-9][0-9]" +
                                 "\..*|2[0-6][0-9]\..*|27[0-7]\..*)))$", string:fileVer)){
                        security_message( port: 0, data: "The target host was found to be vulnerable" );
                }
                exit(0);
 	}
 }
