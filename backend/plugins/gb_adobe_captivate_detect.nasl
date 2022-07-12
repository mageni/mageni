###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_captivate_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Adobe Captivate Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-27
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801266");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Captivate Version Detection");


  script_tag(name:"summary", value:"This script finds the installed Adobe Captivate version and saves
the version in KB.

The script logs in via smb, searches for Adobe Captivate version in the
registry and gets the version from registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AdobeCaptivate.exe");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AdobeCaptivate.exe",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\AdobeCaptivate.exe");
}

if(!registry_key_exists(key:"SOFTWARE\Adobe\Adobe Captivate\")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\Adobe Captivate\")){
    exit(0);
  }
}

foreach key(key_list)
{
  capPath = registry_get_sz(key: key, item:"Path");
  if(capPath)
  {
    capVer = fetch_file_version(sysPath: capPath, file_name: "AdobeCaptivate.exe");

    if(capVer)
    {
      set_kb_item(name:"Adobe/Captivate/Ver", value:capVer);

      cpe = build_cpe(value:capVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:captivate:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:captivate";

      if("64" >< os_arch && "Wow6432Node" >!< key && "x86" >!< capPath)
      {
        set_kb_item(name:"Adobe/Captivate64/Ver", value:capVer);
        cpe = build_cpe(value:capVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:captivate:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:captivate:x64";
      }

      register_product(cpe:cpe, location:capPath);
      log_message(data: build_detection_report(app: "Adobe Captivate",
                                           version: capVer,
                                           install: capPath,
                                           cpe: cpe,
                                           concluded: capVer));
    }
  }
}
