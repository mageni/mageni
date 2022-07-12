###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k-meleon_detect.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# K-Meleon Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800891");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12974 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("K-Meleon Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of K-Meleon Browser
  and sets the result in KB.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "K-Meleon Version Detection";

if(!get_kb_item("SMB/WindowsVersion"))
{
  exit(0);
}

path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\K-Meleon";
kmeleonName = registry_get_sz(key:path, item:"DisplayName");

if("K-Meleon" >< kmeleonName)
{
  kmeleonVer = registry_get_sz(key:path, item:"DisplayVersion");
  if(isnull(kmeleonVer))
  {
    kmeleonPath = registry_get_sz(key:path, item:"UninstallString");
    kmeleonPath = ereg_replace(pattern:'"', replace:"", string:kmeleonPath);

    readme = kmeleonPath - "nsuninst.exe" - "Uninstall.exe" + "readme.txt";
    readFile = smb_read_file(fullpath:readme, offset:0, count:2000);

    ver = eregmatch(pattern:"v([0-9.]+)", string:readFile);
    if(!isnull(ver[1]))
      kmeleonVer = ver[1];
  }
  if(!isnull(kmeleonVer))
  {
    set_kb_item(name:"K-Meleon/Ver", value:kmeleonVer);
    log_message(data:"K-Meleon version " + kmeleonVer + " was detected on the host");

    cpe = build_cpe(value:kmeleonVer, exp:"^([0-9.]+)", base:"cpe:/a:christophe_thibault:k-meleon:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
