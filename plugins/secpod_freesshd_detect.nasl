###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freesshd_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# freeSSHd Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-21
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900959");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("freeSSHd Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of freeSSHd on Windows.

The script logs in via smb, searches for freeSSHd in the registry
and extract version from the name.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently freeSSHd 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sshdName = registry_get_sz(key:key + item, item:"DisplayName");

  if("freeSSHd" >< sshdName)
  {
    sshdVer = eregmatch(pattern:"freeSSHd ([0-9.]+)", string:sshdName);

    if(!isnull(sshdVer[1]))
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"freeSSHd/Ver", value:sshdVer[1]);

      cpe = build_cpe(value:sshdVer[1], exp:"^([0-9.]+)", base:"cpe:/a:freesshd:freesshd:");
      if(isnull(cpe))
        cpe = "cpe:/a:freesshd:freesshd";

      register_product(cpe:cpe, location:insLoc);

      log_message(data: build_detection_report(app: "freeSSHd",
                                               version: sshdVer[1],
                                               install: insLoc,
                                               cpe: cpe,
                                               concluded: sshdName));
    }
  }
}
