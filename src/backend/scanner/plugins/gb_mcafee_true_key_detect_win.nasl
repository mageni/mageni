###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_true_key_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# McAfee True Key Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813322");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-05-02 15:50:09 +0530 (Wed, 02 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("McAfee True Key Version Detection (Windows)");
  script_tag(name:"summary", value:"Detection of installed version
  of McAfee True Key on Windows.

  The script logs in via smb, searches for McAfee True Key in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Intel Security\True Key") &&
   !registry_key_exists(key:"SOFTWARE\TrueKey") &&
   !registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrueKey")){
  exit(0);
}

key = "SOFTWARE\TrueKey\InstallInfo";

trueVer = registry_get_sz(key:key, item:"InstalledVersion");
path = registry_get_sz(key:key, item:"InstallDir");

if(!trueVer)
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrueKey";

  trueName = registry_get_sz(key:key, item:"DisplayName");

  if("Intel Security True Key" >< trueName)
  {
    trueVer = registry_get_sz(key:key, item:"DisplayVersion");
    path = registry_get_sz(key:key, item:"UninstallString");
  }
}

if(trueVer)
{
  if(!path){
    path = "Couldn find the install location from registry";
  }

  set_kb_item(name:"McAfee/TrueKey/Win/Ver", value:trueVer);
  cpe = build_cpe(value:trueVer, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:true_key:");
  if(!cpe)
    cpe = "cpe:/a:mcafee:true_key";

  register_product(cpe:cpe, location:path);
  log_message(data: build_detection_report(app: "McAfee True Key",
                                           version: trueVer,
                                           install: path,
                                           cpe: cpe,
                                           concluded: trueVer));
  exit(0);
}

exit(0);
