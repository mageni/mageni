###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_lync_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Microsoft Lync Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-22
# Updated to support 32 and 64 bit
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
  script_oid("1.3.6.1.4.1.25623.1.0.902843");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-06-13 12:12:12 +0530 (Wed, 13 Jun 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Lync Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Lync.

The script logs in via smb, searches for Microsoft Lync in the registry and
gets the version from 'DisplayVersion' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}


foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    lyncName = registry_get_sz(key:key + item, item:"DisplayName");

    if(("Microsoft Office Communicator" >< lyncName || "Microsoft Lync" >< lyncName)
                       && "Lync Server" >!< lyncName)
    {
      ver = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(ver)
      {
        path = registry_get_sz(key:key + item, item:"InstallLocation");
        if(! path){
          path = "Could not find the install path from registry";
        }

        rlsVer = eregmatch(pattern: "[0-9]+", string: lyncName);

        if("Attendant" >< lyncName)
        {
          set_kb_item(name:"MS/Lync/Attendant/path", value:path);
          set_kb_item(name:"MS/Lync/Installed", value:TRUE);
          set_kb_item(name:"MS/Lync/Attendant6432/Installed", value:TRUE);

          if("32" >< os_arch || "Wow6432Node" >< key) {
            set_kb_item(name:"MS/Lync/Attendant/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendant_x86:", expr:"^([0-9.]+)", insloc:path );
          }
          else if("64" >< os_arch && "Wow6432Node" >!< key)
          {
            set_kb_item(name:"MS/Lync/Attendant64/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendant_x64:", expr:"^([0-9.]+)", insloc:path );
          }
        }

        else if("Attendee" >< lyncName)
        {
          set_kb_item(name:"MS/Lync/Attendee/Ver", value:ver);
          set_kb_item(name:"MS/Lync/Attendee/path", value:path);
          set_kb_item(name:"MS/Lync/Installed", value:TRUE);
          register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendee:", expr:"^([0-9.]+)", insloc:path );
        }

        else if("Microsoft Office Communicator" >< lyncName)
        {
          set_kb_item(name:"MS/Office/Communicator/path", value:path);
          set_kb_item(name:"MS/Office/Communicator6432/Installed", value:TRUE);

          if("64" >< os_arch && "Wow6432Node" >!< key) {
            set_kb_item(name:"MS/Office/Communicator64/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:office_communicator:" + rlsVer[0] + ":x64:", expr:"^([0-9.]+)", insloc:path );
          } else {
            set_kb_item(name:"MS/Office/Communicator/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:office_communicator:" + rlsVer[0] + ":", expr:"^([0-9.]+)", insloc:path );
          }
        }

        else if("Lync Basic" >< lyncName)
        {
          set_kb_item(name:"MS/Lync/Basic/path", value:path);
          set_kb_item(name:"MS/Lync/Installed", value:TRUE);
          set_kb_item(name:"MS/Lync/Basic6432/Installed", value:TRUE);

          if("64" >< os_arch && "Wow6432Node" >!< key) {
            set_kb_item(name:"MS/Lync/Basic64/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync_basic:" + rlsVer[0] + "::x64:", expr:"^([0-9.]+)", insloc:path );
          } else if ("32" >< os_arch || "Wow6432Node" >< key) {
            set_kb_item(name:"MS/Lync/Basic/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync_basic:" + rlsVer[0] + "::x86:", expr:"^([0-9.]+)", insloc:path );
          } else {
            set_kb_item(name:"MS/Lync/Basic/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync_basic:" + rlsVer[0] + ":", expr:"^([0-9.]+)", insloc:path );
          }
        } else {
          set_kb_item(name:"MS/Lync/path", value:path);
          set_kb_item(name:"MS/Lync/Installed", value:TRUE);
          set_kb_item(name:"MS/Lync6432/Installed", value:TRUE);

          if("64" >< os_arch && "Wow6432Node" >!< key) {
            set_kb_item(name:"MS/Lync64/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:"  + rlsVer[0] + "::x64:", expr:"^([0-9.]+)", insloc:path );
          } else if("32" >< os_arch || "Wow6432Node" >< key) {
            set_kb_item(name:"MS/Lync/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:"  + rlsVer[0] + "::x86:", expr:"^([0-9.]+)", insloc:path );
          } else {
            set_kb_item(name:"MS/Lync/Ver", value:ver);
            register_and_report_cpe( app:lyncName, ver:ver, concluded:ver, base:"cpe:/a:microsoft:lync:"  + rlsVer[0] + ":", expr:"^([0-9.]+)", insloc:path );
          }
        }
      }
    }
  }
}
