###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_smb_accessible_shares.nasl 11420 2018-09-17 06:33:13Z cfischer $
#
# Microsoft Windows SMB Accessible Shares
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902425");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11420 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-29 12:08:36 +0530 (Wed, 29 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Windows SMB Accessible Shares");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"The script detects the Windows SMB Accessible Shares and sets the
  result into KB.");

  exit(0);
}

include("smb_nt.inc");

name = kb_smb_name();
domain = kb_smb_domain();
port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();

if(!port){
  port = 139;
}

if(!get_port_state(port)){
 exit(0);
}

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

r = smb_session_setup(soc:soc, login:login, password:pass ,domain:"", prot:prot);
if(!r)
{
  r = smb_session_setup(soc:soc, login:"anonymous", password:pass ,domain:"", prot:prot);
  if(!r)
  {
    close(soc);
    exit(0);
  }
}

uid = session_extract_uid(reply:r);
if(!uid)
{
  close(soc);
  exit(0);
}

foreach s (make_list("A$", "C$", "D$", "ADMIN$", "WINDOWS$", "ROOT$", "WINNT$", "IPC$", "E$"))
{
  r = smb_tconx(soc:soc, name:name, uid:uid, share:s);
  if(r)
  {
    tid = tconx_extract_tid(reply:r);
    if(tid){
      set_kb_item(name:"SMB/Accessible_Shares", value:s);
      report += s + '\n';
    }
  }
}

if( report )
{
  report = 'The following shares were found\n' + report;
  log_message( port:port, data:report );
}

close(soc);
