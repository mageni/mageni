###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_web_apps_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Microsoft Office Web Apps Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802466");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-10-11 10:29:56 +0530 (Thu, 11 Oct 2012)");
  script_name("Microsoft Office Web Apps Detection");


  script_tag(name:"summary", value:"Detects the installed version of Microsoft Office Web Apps.
Microsoft SharePoint Foundation.

The script logs in via smb, searches through the registry and gets the
version and sets the KB.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

if((registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office14.WCSERVER")) ||
  (registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.WacServer")))
{

  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office14.WCSERVER",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.WacServer");
  foreach key(key_list)
  {
    spName = registry_get_sz(key:key, item:"DisplayName");
    if(spName && spName =~ "^Microsoft.*Office Web Apps")
    {
      spVer = registry_get_sz(key:key, item:"DisplayVersion");
      if(spVer)
      {
        insPath = registry_get_sz(key:key, item:"InstallLocation");
        if(!insPath){
          insPath = "Could not find the install location from registry";
        }

        set_kb_item(name:"MS/Office/Web/Apps/Path", value:insPath);
        set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );

        set_kb_item(name:"MS/Office/Web/Apps/Ver", value:spVer);
        set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );
        cpe = build_cpe(value:spVer, exp:"^([0-9.]+)",
                             base:"cpe:/a:microsoft:office_web_apps:");

        if(!cpe)
          cpe = "cpe:/a:microsoft:office_web_apps";

        register_product(cpe:cpe, location:insPath);

        log_message(data: build_detection_report(app:"Microsoft Office Web Apps ",
                                                version:spVer, install:insPath, cpe:cpe,
                                                concluded: spVer));

      }
    }
  }
}

if(!installdetect)
{
  foreach item (registry_enum_keys(key:key))
  {
    spName = registry_get_sz(key:key + item, item:"DisplayName");
    if(spName && egrep(pattern:"^Microsoft.*Office Web Apps\s?$", string:spName))
    {
      installdetect = TRUE;
      spVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(spVer)
      {
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!insPath){
          insPath = "Could not find the install location from registry";
        }
        set_kb_item(name:"MS/Office/Web/Apps/Path", value:insPath);
        set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );

        set_kb_item(name:"MS/Office/Web/Apps/Ver", value:spVer);
        set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );
        cpe = build_cpe(value:spVer, exp:"^([0-9.]+)",
                             base:"cpe:/a:microsoft:office_web_apps:");

        if(!cpe)
          cpe = "cpe:/a:microsoft:office_web_apps";

        register_product(cpe:cpe, location:insPath);

        log_message(data: build_detection_report(app:"Microsoft Office Web Apps ",
                                                version:spVer, install:insPath, cpe:cpe,
                                                concluded: spVer));
      }
    }
  }
}
