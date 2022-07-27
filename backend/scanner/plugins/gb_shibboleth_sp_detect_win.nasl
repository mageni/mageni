###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shibboleth_sp_detect_win.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Shibboleth Service Provider Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
# Updated by Rinu Kuriakose <krinu@secpod.com>
# Updated to new format
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
  script_oid("1.3.6.1.4.1.25623.1.0.801115");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Shibboleth Service Provider Version Detection");

  script_tag(name:"summary", value:"This script detects the installed version of
  Shibboleth Service Provider.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

##Irrespective of architecture Key is same
if(!registry_key_exists(key:"SOFTWARE\Shibboleth")){
  exit(0);
}

shibloc = registry_get_sz(key:"SOFTWARE\Shibboleth", item:"InstallDir");
if(!shibloc){
  shibloc = "Couldn find the install location from registry";
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  shibName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Shibboleth" >< shibName)
  {
    shibVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(shibVer)
    {
      set_kb_item(name:"Shibboleth/SP/Win/Ver", value:shibVer);

      cpe = build_cpe(value:shibVer, exp:"^([0-9.]+)", base:"cpe:/a:internet2:shibboleth-sp:");
      if(!cpe)
        cpe = "cpe:/a:internet2:shibboleth-sp";
      register_and_report_cpe(app:"Shibboleth SP", ver:shibVer, concluded: shibVer,
                              cpename:cpe, insloc:shibloc);
      exit(0);
    }
  }
}
exit(0);