###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_lync_server_detect_win.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Microsoft Lync Server Version Detection
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901218");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-05-15 16:15:45 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Lync Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Detects the installed version of Microsoft Lync Server.

The script logs in via smb, searches for Microsoft Lync Server in the registry and
gets the version from 'DisplayVersion' string in registry");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

keys = registry_enum_keys(key:key);
if(!keys){
  exit(0);
}

foreach item (keys)
{
  dis_name = registry_get_sz(key:key + item, item:"DisplayName");
  if(dis_name =~ "Microsoft Lync Server [0-9]+, Front End Server")
  {
    dis_ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!dis_ver){
      continue;
    }

    path = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!path){
      continue;
    }

    set_kb_item(name:"MS/Lync/Server/Ver", value:dis_ver);

    set_kb_item(name:"MS/Lync/Server/Name", value:dis_name);

    set_kb_item(name:"MS/Lync/Server/path", value:path);

    cpe = build_cpe(value:dis_ver, exp:"^([0-9.]+)",
                        base:"cpe:/a:microsoft:lync_server:");

    if(!isnull(cpe))
      register_product(cpe:cpe, location:path);

    log_message(data: build_detection_report(app:dis_name, version:dis_ver,
                install:path, cpe:cpe, concluded:dis_ver));
  }
}
