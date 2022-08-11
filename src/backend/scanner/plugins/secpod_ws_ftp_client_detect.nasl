##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ws_ftp_client_detect.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# Iswitch WS-FTP Client Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SePod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902170");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Iswitch WS-FTP Client Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Iswitch
  WS-FTP Client.

  The script logs in via smb, searches for Iswitch WS-FTP Client in the registry
  and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Ipswitch\WS_FTP") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Ipswitch\WS_FTP")){
  exit(0);
}


if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if(("Ipswitch" >< appName) || ("WS_FTP" >< appName))
    {
      appAdd = registry_get_sz(key:key + item, item:"DisplayIcon");
      appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if("ftppro" >< appAdd){
        install = TRUE;
      } else if(appLoc)
      {
        ##If version is fetched, file is present and so professional edition
        checkpro = fetch_file_version(sysPath:appLoc, file_name:"wsftppro.exe");
        if(checkpro){
          install = TRUE;
        }
      } else {
          exit(0);
      }

      if(install)
      {
        ipsVer = registry_get_sz(key:key + item, item:"DisplayVersion");

        if(ipsVer)
        {
          if(!appLoc){
            appLoc = "Couldn find the install location from registry";
          }

          set_kb_item(name:"Ipswitch/WS_FTP_Pro/Client/Ver", value:ipsVer);

          cpe = build_cpe(value:ipsVer, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp:");
          if(isnull(cpe))
            cpe = "cpe:/a:ipswitch:ws_ftp";

          ## 64 bit apps on 64 bit platform
          if("x64" >< osArch && "Wow6432Node" >!< key)
          {
            set_kb_item(name:"Ipswitch/WS_FTP_Pro64/Client/Ver", value:ipsVer);

            cpe = build_cpe(value:ipsVer, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp:x64:");
            if(isnull(cpe))
              cpe = "cpe:/a:ipswitch:ws_ftp:x64";
          }
          register_product(cpe:cpe, location:appLoc);
          log_message(data: build_detection_report(app: appName,
                                                   version: ipsVer,
                                                   install: appLoc,
                                                   cpe: cpe,
                                                   concluded: ipsVer));
        }
      }
    }
  }
}
