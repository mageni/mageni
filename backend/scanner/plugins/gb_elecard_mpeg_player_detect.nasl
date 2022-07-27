###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elecard_mpeg_player_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# Elecard MPEG Player Application Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800510");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Elecard MPEG Player Application Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of Elecard MPEG
  Player application and sets the version in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Elecard MPEG Player Application Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Elecard")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

keys = registry_enum_keys(key:key);

foreach item(keys)
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if(appName == "Elecard MPEG Player")
  {
    path = registry_get_sz(key:key + item, item:"InstallLocation");
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:path);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:path+ "\MpegPlayer.exe");
  }
}

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

eleVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:1067429);
close(soc);
if(eleVer != NULL)
{
  set_kb_item(name:"Elecard/Player/Ver", value:eleVer);
  log_message(data:"Elecard Player version " + eleVer +
                     " was detected on the host");

  cpe = build_cpe(value:eleVer, exp:"^([0-9.]+)", base:"cpe:/a:elecard:elecard_mpeg_player:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  exit(0);
}
