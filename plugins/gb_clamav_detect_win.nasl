###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# ClamAV Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Modified By: Antu sanadi <santu@secpod.com> on 2010-04-09
# Modified to detect version of latest products also
#
# Modified By: Madhuri D <dmadhuri@secpod.com> on 2011-08-27
# Modified to detect latest version
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-17
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800555");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ClamAV Version Detection (Windows)");


  script_tag(name:"summary", value:"This script retrieves ClamAV Version for Windows and saves the result in KB.

The script logs in via smb, searches for ClamWin or ClamAV or Immunet string in
the registry and gets the version from registry");

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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}


foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    clamName = registry_get_sz(key:key + item, item:"DisplayName");
    if("ClamWin" >< clamName || "ClamAV" >< clamName)
    {
      clamVer = eregmatch(pattern:"ClamWin Free Antivirus ([0-9.]+)", string:clamName);
      clamPath = "Couldn find the install location from registry";
      if(clamVer[1]){
        clamVer = clamVer[1];
      }else{
        clamVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      }
      if(clamVer)
      {
        set_kb_item(name:"ClamAV/installed", value:TRUE);
        set_kb_item(name:"ClamAV/Win/Ver", value:clamVer);

        cpe = build_cpe(value:clamVer, exp:"^([0-9.]+)", base:"cpe:/a:clamav:clamav:");
        if(isnull(cpe))
          cpe = "cpe:/a:clamav:clamav";
      }
    }
  }

  if(!clamVer)
  {
    key = key + "Immunet Protect\";
    clamname = registry_get_sz(key:key , item:"DisplayName");
    if("ClamAV for Windows"  >< clamname || "Immunet" >< clamname)
    {
      clamVer = registry_get_sz(key:key , item:"DisplayVersion");
      clamPath = registry_get_sz(key:key , item:"UninstallString");
      clamPath = clamPath - "uninstall.exe" ;

      if(clamVer)
      {
        set_kb_item(name:"ClamAV/installed", value:TRUE);
        set_kb_item(name:"ClamAV/Win/Ver", value:clamVer);
        cpe = build_cpe(value:clamVer, exp:"^([0-9.]+)", base:"cpe:/a:clamav:clamav:");
        if(isnull(cpe))
          cpe = "cpe:/a:clamav:clamav";
      }
    }
  }

  ## application sets value in registry WOW6432 for 64-bit and also Path is not available
  ## for some installs, so it registers falsely as 64-bit for installs where Path cannot
  ## be fetched.
  if(clamVer)
  {
    if("64" >< os_arch && "x86" >!< clamPath)
    {
      set_kb_item(name:"ClamAV/installed", value:TRUE);
      set_kb_item(name:"ClamAV64/Win/Ver", value:clamVer);

      cpe = build_cpe(value:clamVer, exp:"^([0-9.]+)", base:"cpe:/a:clamav:clamav:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:clamav:clamav:x64";
    }
    register_product(cpe:cpe, location:clamPath);

    log_message(data: build_detection_report(app: "Clam Anti Virus",
                                             version: clamVer,
                                             install: clamPath,
                                             cpe: cpe,
                                             concluded: clamVer));

  }
}
