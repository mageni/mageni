##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_reg_enum.nasl 11706 2018-10-01 09:48:48Z cfischer $
#
# Enumerates List of Windows Hotfixes
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
  script_oid("1.3.6.1.4.1.25623.1.0.900012");
  script_version("$Revision: 11706 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 11:48:48 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_name("Enumerates List of Windows Hotfixes");
  script_family("Windows");
  script_copyright("Copyright (C) 2008 SecPod");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsName");

  script_tag(name:"summary", value:"This script is enumerating the list of all installed Windows hotfixes
  on the remote host and saves the enumerated info into the internal Knowledge Base for later use.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

function crawlLevel(key, level, maxlevel, soc, uid, tid, pipe, handle){

  local_var key, level, maxlevel, soc, uid, tid, pipe, handle;
  local_var list, key_h, entries;

  list = make_list();

  if(level >= maxlevel){
    return list;
  }

  key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
  if(key_h){
    entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
  }

  if(!isnull(key_h)){
    registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
  }

  foreach item (entries){
    list = make_list(list, key + "\" + item);
  }
  return list;
}

function crawl(key, level, maxlevel, soc, uid, tid, pipe, handle){

  local_var key, level, maxlevel, soc, uid, tid, pipe, handle;
  local_var enum, enumList, listLevel1, listLevel2;

  enum = make_list();

  if(level >= maxlevel){
    return enum;
  }

  enumList = crawlLevel(key:key, level:level, maxlevel:maxlevel, soc:soc, uid:uid, tid:tid, pipe:pipe, handle:handle);
  if(max_index(enumList) > 0){
    enum = make_list(enum, enumList);
  }

  foreach item (enumList){
    listLevel1 = crawlLevel(key:item, level:level+1, maxlevel:maxlevel, soc:soc, uid:uid, tid:tid, pipe:pipe, handle:handle);
    if(max_index(listLevel1) > 0){
      enum = make_list(enum, listLevel1);
    }

    foreach item (listLevel1){
      listLevel2 = crawlLevel(key:item, level:level+1, maxlevel:maxlevel, soc:soc, uid:uid, tid:tid, pipe:pipe, handle:handle);
      if(max_index(listLevel2) > 0){
        enum = make_list(enum, listLevel2);
      }
    }
  }
  return enum;
}

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

soc = open_sock_tcp(infos["transport_port"]);
if(!soc){
  exit(0);
}

name = infos["netbios_name"];
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

r = smb_session_setup(soc:soc, login:infos["username_plain"], password:infos["password"], domain:infos["domain"], prot:prot);
if(!r){
  close(soc);
  exit(0);
}

uid = session_extract_uid(reply:r);
if(!uid){
  close(soc);
  exit(0);
}

r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
if(!r){
  close(soc);
  exit(0);
}

tid = tconx_extract_tid(reply:r);
if(!tid){
  close(soc);
  exit(0);
}

r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r){
  close(soc);
  exit(0);
}

pipe = smbntcreatex_extract_pipe(reply:r);
r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r){
  close(soc);
  exit(0);
}

# nb: Windows XP and similar
handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
location1 = "SOFTWARE\Microsoft\Updates";
location2 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix";

list = make_list(crawl(key:location1, level:0, maxlevel:3, soc:soc, uid:uid, tid:tid, pipe:pipe, handle:handle),
                 crawl(key:location2, level:0, maxlevel:1, soc:soc, uid:uid, tid:tid, pipe:pipe, handle:handle));

close(soc);

if(max_index(list) > 0){
  set_kb_item(name:"SMB/registry_enumerated", value:TRUE);
}

# e.g.:
# SOFTWARE\Microsoft\Updates\Windows XP\SP4\KB951376-v2
# SOFTWARE\Microsoft\Updates\Windows Media Format 11 SDK\KB929399
# SOFTWARE\Microsoft\Updates\Windows XP\SP-1\KB909520
# SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\KB982381-IE8
# SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q147222
foreach item (list){
  if(egrep(pattern:"\\(KB|Q|M)[0-9]+", string:item)){
    item = str_replace(find:"\", replace:"/", string:item);
    set_kb_item(name:"SMB/Registry/HKLM/" + item, value:TRUE);
  }
}

# nb: Windows Vista, Windows 7, Windows 2008
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\";
if(!registry_key_exists(key:key)){
  exit(0);
}

list = registry_enum_keys(key:key);
if(max_index(list) > 0){
  set_kb_item(name:"SMB/registry_enumerated", value:TRUE);
}

# e.g.
# Package_8_for_KB938371~31bf3856ad364e35~amd64~~6.0.1.25
# Package_for_KB937287_client~31bf3856ad364e35~amd64~~6.0.1.18000
foreach item (list){
  if(egrep(pattern:"[P|p]ackage.?[0-9]*.?for.?KB.*", string:item)){
    path = key + item;
    path = str_replace(find:"\", replace:"/", string:path);
    set_kb_item(name:"SMB/Registry/HKLM/" + path, value:TRUE);
  }
}

exit(0);