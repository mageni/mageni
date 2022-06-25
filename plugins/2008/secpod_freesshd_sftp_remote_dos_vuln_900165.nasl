##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freesshd_sftp_remote_dos_vuln_900165.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: freeSSHd SFTP 'rename' and 'realpath' Remote DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900165");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_cve_id("CVE-2008-4762");
  script_bugtraq_id(31872);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("freeSSHd SFTP 'rename' and 'realpath' Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://freesshd.com/index.php");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6800");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32366/");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service.");

  script_tag(name:"affected", value:"freeSSHd freeSSHd version 1.2.1.14 and prior on Windows (all)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to freeSSHd version 1.2.6 or later.");

  script_tag(name:"summary", value:"The host is running freeSSHd SSH server and is prone to
  remote denial of service vulnerability.

  NULL pointer de-referencing errors in SFTP 'rename' and 'realpath' commands.
  These can be exploited by passing overly long string passed as an argument to
  the affected commands.");

  script_xref(name:"URL", value:"http://www.freesshd.com/index.php?ctt=download");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sshdPath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\FreeSSHDService", item:"ImagePath");
if(!sshdPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sshdPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sshdPath);

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

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                      prot:prot);
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

fileVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid);

if(egrep(pattern:"^1\.([01](\..*)|2(\.[01](\.[0-9]|\.1[0-4])?)?)$",
         string:fileVer)){
  security_message(port:0);
}
