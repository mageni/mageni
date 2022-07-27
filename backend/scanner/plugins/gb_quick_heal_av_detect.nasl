###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_heal_av_detect.nasl 2013-12-30 14:34:39Z veerendrag$
#
# Quick Heal Anti-Virus Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-22
# To support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804180");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-30 17:37:18 +0530 (Mon, 30 Dec 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Quick Heal Anti-Virus Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of Quick Heal Anti-Virus.

The script logs in via smb, searches for Quick Heal in the registry and gets
the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Quick Heal AntiVirus Pro")){
    exit(0);
}

## Key is independent of platform
key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Quick Heal AntiVirus Pro\");

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  qhName = registry_get_sz(key:key, item:"DisplayName");

  if("Quick Heal AntiVirus Pro" >< qhName)
  {
    qhPath = registry_get_sz(key:key, item:"InstallLocation");
    if(qhPath)
    {
      qhVer = fetch_file_version(sysPath: qhPath, file_name:"scanner.exe");
      if(qhVer)
      {
        set_kb_item(name:"QuickHeal/Antivirus6432/Pro/Installed", value:TRUE);
        set_kb_item(name:"QuickHeal/Antivirus/Pro", value:qhVer);
        register_and_report_cpe( app:qhName, ver:qhVer, base:"cpe:/a:quickheal:antivirus_pro:", expr:"^([0-9.]+)", insloc:qhPath );
        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch) {
          set_kb_item(name:"QuickHeal/Antivirus64/Pro", value:qhVer);
          register_and_report_cpe( app:qhName, ver:qhVer, base:"cpe:/a:quickheal:antivirus_pro:x64:", expr:"^([0-9.]+)", insloc:qhPath );
        }
      }
    }
  }
}
