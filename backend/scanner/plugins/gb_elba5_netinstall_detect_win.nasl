##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elba5_netinstall_detect_win.nasl 12981 2019-01-08 15:12:42Z mmartin $
#
# RACON Software ELBA5 Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107441");
  script_version("$Revision: 12981 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 16:12:42 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-08 16:13:29 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("RACON Software ELBA5 Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of RACON Software ELBA5 for Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "ELBA5") continue;

    set_kb_item(name:"racon_software/elba/win/detected", value:TRUE);

    split = split( appName, sep:" " );
    appName = split[0];

    version = "unknown";
    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

    path = location + '\\properties\\config.properties.defaults';

    version_info = smb_read_file(fullpath:path, offset:0, count:3000);
    revq = eregmatch(pattern:"SUBVERSION=([A-Z])0*([1-9]+)", string:version_info);
    rev = revq[1] + revq[2];
    versq = eregmatch(pattern:"VERSION=([0-9]+)", string:version_info);
    vers = versq[1];
    concluded = appName + versq[0] + " " + revq[0];

    if(vers)
      _vers = eregmatch(string:vers, pattern:"([0-9])([0-9])([0-9])([0-9])");

    if(_vers)
      version = _vers[1] + "." + _vers[2] + "." + _vers[3] + "." + _vers[4] + " " + rev;

    register_and_report_cpe(app:appName , ver:version, concluded:concluded,
                          base:"cpe:/a:racon_software:elba5:", expr:"^([0-9.]+) ?([A-Z0-9]+)?", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
