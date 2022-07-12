##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_silverlight_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Microsoft Silverlight Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801934");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Silverlight Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Silverlight on Windows.

The script logs in via smb, searches for Silverlight in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Silverlight")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Silverlight")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Silverlight");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Silverlight",
                        "SOFTWARE\Microsoft\Silverlight");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  msl_ver = registry_get_sz(key:key, item:"Version");
  if("Wow6432Node" >< key){
    unKey = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
  } else {
    unKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  }

  foreach item (registry_enum_keys(key:unKey))
  {
    app_name = registry_get_sz(key:unKey + item, item:"DisplayName");
    if("Microsoft Silverlight" >!< app_name){
       continue;
    }

    set_kb_item(name:"Microsoft/Silverlight/Installed", value:TRUE);

    if(!msl_ver || msl_ver == "0"){
      msl_ver = registry_get_sz(key:unKey + item, item:"DisplayVersion");
    }

    ins_loc = registry_get_sz(key:unKey + item, item:"InstallLocation");
    break;
  }

  if(msl_ver && "Microsoft Silverlight" >< app_name) {

   if(!ins_loc){
      ins_loc = "Couldn find the install location from registry";
    }

    ## 64 bit apps on 64 bit platform
    if("x64" >< os_arch && "Wow6432Node" >!< key) {
      set_kb_item(name:"Microsoft/Silverlight64/Ver", value:msl_ver);
      register_and_report_cpe( app:"Microsoft Silverlight", ver:msl_ver, base:"cpe:/a:microsoft:silverlight:x64:", expr:"^([0-9.]+)", insloc:ins_loc );
    } else {
      set_kb_item(name:"Microsoft/Silverlight/Ver", value:msl_ver);
      register_and_report_cpe( app:"Microsoft Silverlight", ver:msl_ver, base:"cpe:/a:microsoft:silverlight:", expr:"^([0-9.]+)", insloc:ins_loc );
    }
  }
}
