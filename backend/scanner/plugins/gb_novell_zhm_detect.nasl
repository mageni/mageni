###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zhm_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Novell ZENworks Handheld Management Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-27
# Updated according to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801644");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Novell ZENworks Handheld Management Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Novell ZENworks Handheld Management
on Windows.

The script logs in via smb, searches for ZENworks Handheld Management Server
in the registry and gets the version from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!registry_key_exists(key:"SOFTWARE\Novell\ZENworks\Handheld Management\Server"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Novell\ZENworks\Handheld Management\Server")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Novell\ZENworks\Handheld Management\Server\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Novell\ZENworks\Handheld Management\Server\";
}

AppName = registry_get_sz(key:key, item:"Display Name");
if("ZENworks Handheld Management Server" >< AppName)
{
  AppVer = registry_get_sz(key:key, item:"Version");
  if(AppVer != NULL)
  {
    appPath = registry_get_sz(key:key, item:"InstallPath");
    if(!appPath){
      appPath = "Could not find the install Location from registry";
    }

    set_kb_item(name:"Novell/ZHM/Ver", value:AppVer);

    cpe = build_cpe(value:AppVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:zenworks_handheld_management:");
    if(isnull(cpe))
      cpe = "cpe:/a:novell:zenworks_handheld_management";

    register_product(cpe:cpe, location:appPath);

    log_message(data: build_detection_report(app: AppName,
                                               version: AppVer,
                                               install: appPath,
                                               cpe: cpe,
                                               concluded: AppVer));
    exit(0);
  }
}

exit(0);
