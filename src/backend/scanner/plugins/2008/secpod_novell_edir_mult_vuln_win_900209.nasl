##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_edir_mult_vuln_win_900209.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Novell eDirectory Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900209");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094", "CVE-2008-5095");
  script_bugtraq_id(30947);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_name("Novell eDirectory Multiple Vulnerabilities (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31684");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020788.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020787.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020786.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020785.html");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=RH_B5b3M6EQ~");

  script_tag(name:"summary", value:"This host is running Novell eDirectory, which is prone to XSS,
  Denial of Service, and Remote Code Execution Vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaw are due to,

  - errors in HTTP Protocol Stack that can be exploited to cause heap
  based buffer overflow via a specially crafted language/content-length headers.

  - input passed via unspecified parameters to the HTTP Protocol Stack is
  not properly sanitzed before being returned to the user.

  - Multiple unknown error exist in LDAP and NDS services.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8 SP2 and prior versions on Windows 2000/2003.");

  script_tag(name:"solution", value:"Apply 8.8 Service Pack 3.");

  script_tag(name:"impact", value:"Successful Remote exploitation will allow execution of
  arbitrary code, heap-based buffer overflow, Cross Site Scripting
  attacks, or cause memory corruption.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 eDirVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\Uninstall\NDSonNT", item:"DisplayName");
 if(!eDirVer){
	exit(0);
 }

 if(!(egrep(pattern:"^Novell eDirectory ([0-7]\..*|8\.[0-7]( .*)?|8\.8( SP[0-2])?)$",
            string:eDirVer))){
        exit(0);
 }

 eDirPath = registry_get_sz(key:"SOFTWARE\NOVELL\NDS\NDSSNMPAgent" +
                                "\CurrentVersion", item:"Pathname");
 if(!eDirPath){
        exit(0);
 }

 eDirPath = eDirPath - "ndssnmpsa.dll";

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:eDirPath);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:eDirPath +
                      "nauditds.dlm ");

 name   =  kb_smb_name();
 login  =  kb_smb_login();
 pass   =  kb_smb_password();
 domain =  kb_smb_domain();
 port   =  kb_smb_transport();

 soc = open_sock_tcp(port);
 if(!soc){
        exit(0);
 }

 r = smb_session_request(soc:soc, remote:name);
 if(!r){
        close(soc);
        exit(0);
 }

 prot = smb_neg_prot(soc:soc);
 if(!prot){
        close(soc);
        exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
 if(!r){
        close(soc);
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid){
        close(soc);
        exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
 if(!r){
        close(soc);
        exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if(!tid){
        close(soc);
        exit(0);
 }

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid){
        close(soc);
        exit(0);
 }

 fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 close(soc);

 if(!fsize){
	exit(0);
 }

 if(fsize < 110592){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
