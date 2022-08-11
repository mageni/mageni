###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justsystems_ichitaro_prdts_detect.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# JustSystems Ichitaro Product(s) Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800542");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10883 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("JustSystems Ichitaro Product(s) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed product version of Ichitaro
  and Ichitaro viewer and sets the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Justsystem")){
  exit(0);
}

viewerPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\TAROVIEW.EXE", item:"Path");
if(viewerPath)
{
  viewerVer = fetch_file_version(sysPath:viewerPath, file_name:"TAROVIEW.EXE");

  if(viewerVer != NULL)
  {
    set_kb_item(name:"Ichitaro/Ichitaro_or_Viewer/Installed", value:TRUE);
    set_kb_item(name:"Ichitaro/Viewer/Ver", value:viewerVer);

    register_and_report_cpe(app:"Ichitaro Viewer", ver:viewerVer, base:"cpe:/a:justsystem:ichitaro_viewer:5.1",
                            expr:"^(19\..*)", insloc:viewerPath);
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("ATOK" >< appName)
  {
    appVer = eregmatch(pattern:"ATOK ([0-9.]+)", string:appName);
    if(appVer[1] != NULL)
    {
      set_kb_item(name:"Ichitaro/Ichitaro_or_Viewer/Installed", value:TRUE);
      set_kb_item(name:"Ichitaro/Ver", value:appVer[1]);

     register_and_report_cpe(app:"Ichitaro", ver:appVer[1], base:"cpe:/a:ichitaro:ichitaro:",
                            expr:"^([0-9.]+)");
    }
    exit(0);
  }
}
