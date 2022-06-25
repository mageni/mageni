###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_irfanview_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# IrfanView Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900376");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11279 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IrfanView Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed
  version of IrfanView and sets the reuslt in KB.");
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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView64",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  irfName = registry_get_sz(key:key, item:"DisplayName");

  irfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
  irfPath = registry_get_sz(key:key + item, item:"InstallLocation");
  if(!irfPath){
    irfPath = "Unable to fetch the install location";
  }

  if(!irfVer)
  {
    ##Keeping old logic in case of failure to get version.
    path = registry_get_sz(key:key, item:"UninstallString");
    irViewPath = path - "\iv_uninstall.exe" + "\i_view32.exe";
    irfVer = GetVersionFromFile(file:irViewPath, verstr:"prod");
  }

  if(irfVer)
  {
    set_kb_item(name:"IrfanView/Ver", value:irfVer);
    cpe = build_cpe(value:irfVer, exp:"^([0-9.]+)", base:"cpe:/a:irfanview:irfanview:");
    if(isnull(cpe)){
      cpe = "cpe:/a:irfanview:irfanview";
    }

    if("x64" >< os_arch && "64-bit" >< irfName)
    {
      set_kb_item(name:"IrfanView/Ver/x64", value:irfVer);
      cpe = build_cpe(value:irfVer, exp:"^([0-9.]+)", base:"cpe:/a:irfanview:irfanview:x64:");
      if(isnull(cpe)){
        cpe = "cpe:/a:irfanview:irfanview:x64";
      }
    }

    register_product(cpe:cpe, location:irfPath);
    log_message(data: build_detection_report(app: irfName,
                                             version: irfVer,
                                             install: irfPath,
                                             cpe: cpe,
                                             concluded: irfVer));
  }
}
exit(0);