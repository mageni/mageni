###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_informix_dynamic_server_detect_win.nasl 10880 2018-08-10 09:27:43Z cfischer $
#
# IBM Informix Dynamic Server Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated by Kashinath T <tkashinath@secpod.com>
# - Updated to register cpe and to support 64bit
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902545");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10880 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 11:27:43 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Informix Dynamic Server Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Detects the installed version of
  IBM Informix Dynamic Server

  The script logs in via smb, searches for IBM Informix Dynamic Server in the
  registry and gets the version from 'DisplayVersion' string from registry.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\IBM\IBM Informix Dynamic Server") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\IBM\IBM Informix Dynamic Server")){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");

  if(name =~ "IBM Informix Dynamic Server$")
  {
    version = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(version)
    {
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");

      set_kb_item(name:"IBM/Informix/Dynamic/Server/Win/Ver", value:version);

      cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:ibm:informix_dynamic_server:");
      if(isnull(cpe))
         cpe = "cpe:/a:ibm:informix_dynamic_server";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: name,
                                               version: version,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: version));
      exit(0);
    }
  }
}
