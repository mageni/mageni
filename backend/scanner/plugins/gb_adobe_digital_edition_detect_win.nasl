###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_edition_detect_win.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# Adobe Digital Edition Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804300");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-03 13:43:16 +0530 (Mon, 03 Feb 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Edition Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Digital Edition on Windows.

The script logs in via smb, searches for Adobe Digital in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe"))
{
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
    digName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Adobe Digital Editions" >< digName)
    {
      digVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      digPath = registry_get_sz(key:key + item, item:"UninstallString");
      if(!digPath){
        digPath = "Couldn find the install location from registry";
      }
      else
      {
        digPath = digPath - "uninstall.exe";
      }

      if(digVer)
      {
        set_kb_item(name:"AdobeDigitalEdition/Win/Ver", value:digVer);

        cpe = build_cpe(value:digVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:digital_editions:");
        if(!cpe)
          cpe = "cpe:/a:adobe:digital_editions";

        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"AdobeDigitalEdition64/Win/Ver", value:digVer);

          cpe = build_cpe(value:digVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:digital_editions:x64:");
          if(!cpe)
            cpe = "cpe:/a:adobe:digital_editions:x64";
        }
        register_product(cpe:cpe, location:digPath);
        log_message(data: build_detection_report(app: "Adobe Digital Edition",
                                                 version: digVer,
                                                 install: digPath,
                                                 cpe: cpe,
                                                 concluded: digVer));
      }
    }
  }
}