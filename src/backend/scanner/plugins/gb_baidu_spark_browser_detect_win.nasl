###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_baidu_spark_browser_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Baidu Spark Browser Version Detection (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804900");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-08-25 14:40:48 +0530 (Mon, 25 Aug 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Baidu Spark Browser Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Baidu Spark Browser.

The script logs in via smb, searches for Baidu Spark Browser in the registry and
gets the version from registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node";
}

key = key + "\Baidu\Spark";
if(!registry_key_exists(key:key)){
  exit(0);
}

baiduVer = registry_get_sz(key: key, item:"Version");
if(!baiduVer){
  exit(0);
}

insPath = registry_get_sz(key: key, item:"installDir");
if(!insPath){
  insPath = "Unable to find the Installed Path from registry";
}

if(baiduVer)
{
  set_kb_item(name:"BaiduSparkBrowser/Win/Ver", value: baiduVer);

  cpe = build_cpe(value:baiduVer, exp:"^([0-9.]+)", base:"cpe:/a:baidu:spark_browser:");
  if(isnull(cpe)){
    cpe = 'cpe:/a:baidu:spark_browser';
  }

  register_product(cpe:cpe, location:insPath);

  log_message(data: build_detection_report(app: "Baidu Spark Browser",
                                           version: baiduVer,
                                           install: insPath,
                                           cpe: cpe,
                                           concluded: baiduVer));
}
