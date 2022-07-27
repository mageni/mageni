###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_symphony_detect_win.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# IBM Lotus Symphony Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802226");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("IBM Lotus Symphony Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of IBM Lotus Symphony on Windows.

The script logs in via smb, searches for IBM Lotus Symphony in the registry,
gets the from registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Lotus\Symphony") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Lotus\Symphony")){
  exit(0);
}

if("x86" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    gsName = registry_get_sz(key:key + item, item:"DisplayName");
    if("IBM Lotus Symphony" >< gsName)
    {
      gsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(gsVer)
      {
        path = registry_get_sz(key:key + item , item:"InstallLocation");
        if(!path){
          path = "Could not find the install location from registry";
        }

        set_kb_item(name:"IBM/Lotus/Symphony/Win/Ver", value:gsVer);

        cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:lotus_symphony:");
        if(isnull(cpe))
          cpe = 'cpe:/a:ibm:lotus_symphony';

        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"IBM/Lotus/Symphony64/Win/Ver", value:gsVer);

          cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:lotus_symphony:x64:");
          if(isnull(cpe))
            cpe = 'cpe:/a:ibm:lotus_symphony:x64';
        }
        register_product(cpe:cpe, location:path);
        log_message(data: build_detection_report(app: "IBM Lotus Symphony",
                                                 version: gsVer,
                                                 install: path,
                                                 cpe: cpe,
                                                 concluded: gsVer));
      }
    }
  }
}
