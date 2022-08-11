###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avant_browser_detect.nasl 12977 2019-01-08 13:29:01Z cfischer $
#
# Avant Browser Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800870");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12977 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:29:01 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Avant Browser Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of Avant Browser
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Avant Browser Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AvantBrowser";
avantName = registry_get_sz(key:path, item:"DisplayName");

if("Avant Browser" >< avantName)
{
  avantPath = registry_get_sz(key:path, item:"UninstallString");
  avantPath = eregmatch(pattern:'\"(.*)\"', string:avantPath);

  foreach item (make_list("avant.exe", "iexplore.exe", "abrowser.exe"))
  {
    path1 = avantPath[1] - "uninst.exe" + item;
    avantVer = GetVersionFromFile(file:path1, offset:250000);

    if(!isnull(avantVer) && avantVer =~ "^0\.0\..*")
    {
      path2 = avantPath[1] - "uninst.exe" + "abrowser.ini";
      read = smb_read_file(fullpath:path2, offset:0, count:20000);
      avantVer = eregmatch(pattern:"VersionInfo=([0-9.]+)", string:read);

      if(!isnull(avantVer[1]))
        avantVer = avantVer[1];
    }

    if(!isnull(avantVer))
    {
      set_kb_item(name:"AvantBrowser/Ver", value:avantVer);
      log_message(data:"Avant Browser version " + avantVer + " was detected on the host");

      cpe = build_cpe(value:avantVer, exp:"^([0-9.]+)", base:"cpe:/a:avant_force:avant_browser:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
