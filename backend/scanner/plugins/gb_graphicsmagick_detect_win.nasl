###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_detect_win.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# GraphicsMagick Version Detection (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800514");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_name("GraphicsMagick Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  GraphicsMagick.

  The script logs in via smb, searches for Graphics Magick in the registry
  and gets the version from 'Version' string from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\GraphicsMagick") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\GraphicsMagick")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\GraphicsMagick\Current");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\GraphicsMagick\Current",
                        "SOFTWARE\Wow6432Node\GraphicsMagick\Current");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  gmVer = registry_get_sz(key:key, item:"Version");
  if(gmVer)
  {
    gmPath = registry_get_sz(key:key, item:"ConfigurePath");
    if(!gmPath){
      gmPath = "Unable to find the install location from registry";
    }

    set_kb_item(name:"GraphicsMagick/Win/Installed", value:TRUE);

    if("64" >< os_arch && "Wow6432Node" >!< key) {
      set_kb_item(name:"GraphicsMagick64/Win/Ver", value:gmVer);
      register_and_report_cpe( app:"GraphicsMagick", ver:gmVer, base:"cpe:/a:graphicsmagick:graphicsmagick:x64:", expr:"^([0-9.]+)", insloc:gmPath );
    } else {
      set_kb_item(name:"GraphicsMagick/Win/Ver", value:gmVer);
      register_and_report_cpe( app:"GraphicsMagick", ver:gmVer, base:"cpe:/a:graphicsmagick:graphicsmagick:", expr:"^([0-9.]+)", insloc:gmPath );
    }
  }
}
