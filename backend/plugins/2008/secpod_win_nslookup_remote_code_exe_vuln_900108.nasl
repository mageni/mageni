##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_win_nslookup_remote_code_exe_vuln_900108.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Microsoft Windows NSlookup.exe Remote Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900108");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3648");
  script_bugtraq_id(30636);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Windows");
  script_name("Microsoft Windows NSlookup.exe Remote Code Execution Vulnerability");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://securitytracker.com/id?1020711");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/44423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30636/solution");
  script_xref(name:"URL", value:"http://www.nullcode.com.ar/ncs/crash/nsloo.htm");
  script_tag(name:"summary", value:"The host is running Windows XP SP2, which prone to remote code
execution vulnerability.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error in 'NSlookup.exe' file,
which could be exploited by attackers.");
  script_tag(name:"affected", value:"Microsoft Windows 2K and XP.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"impact", value:"Successful exploitation causes remote code execution, and
Denial-of-Service.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


 include("smb_nt.inc");
 include("secpod_smb_func.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 winPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
 if(!winPath){
  exit(0);
 }

 winPath += "\nslookup.exe";
 share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:winPath);
 file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:winPath);

 name = kb_smb_name();
 domain = kb_smb_domain();
 login = kb_smb_login();
 pass = kb_smb_password();
 port = kb_smb_transport();
 soc = open_sock_tcp(port);
 if(!soc){
        exit(0);
 }

 r = smb_session_request(soc:soc, remote:name);
 if(!r){
        exit(0);
 }

 prot = smb_neg_prot(soc:soc);
 if(!prot){
        exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
 if(!r){
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid){
        exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
 if(!r){
        exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if(!tid){
        exit(0);
 }

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid){
        exit(0);
 }

 winVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod", offset:50000);

 if(egrep(pattern:"^5\.(0?1\.2600\.([01]?[0-9]?[0-9]?[0-9]|20[0-9][0-9]|21[0-7]" +
      "[0-9]|2180)|0?0\.2195\.([0-5]?[0-9]?[0-9]?[0-9]|6[0-5][[0-9]" +
      "[0-9]|66[0-5][0-9]|666[0-3]))$", string:winVer)){
  security_message(port:port);
 }
