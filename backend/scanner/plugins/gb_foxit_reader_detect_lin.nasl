###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_detect_lin.nasl 12733 2018-12-10 09:17:04Z cfischer $
#
# Foxit Reader Version Detection (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809332");
  script_version("$Revision: 12733 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 10:17:04 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-11-08 17:20:13 +0530 (Tue, 08 Nov 2016)");
  script_name("Foxit Reader Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of
  Foxit Reader on Linux.

  The script logs in via ssh, searches for foxitreader and queries the
  version from 'FoxitReader' file.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("ReaderLite4Linux.*[0-9\\.\\+].*updater:");

Foxit_Name = find_file(file_name:"FoxitReader", file_path:"/opt/", useregex:TRUE, regexpar:"$", sock:sock);
if(!Foxit_Name){
  ssh_close_connection();
  exit(0);
}

foreach binaryName(Foxit_Name){

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  FoxitVer = get_bin_version(full_prog_name:"grep", version_argv:arg, ver_pattern:"", sock:sock);
  if(!FoxitVer[1]) continue;

  FoxitVer = FoxitVer[1];

  # nb: Replace non readable chars with ''
  FoxitVer = str_replace(find:raw_string(0x00), replace:"", string:FoxitVer);

  FoxitVer = eregmatch(pattern:"ReaderLite4Linux([0-9.]+)", string:FoxitVer);
  if(FoxitVer[1]){

    set_kb_item(name:"foxit/reader/linux/ver", value:FoxitVer[1]);

    register_and_report_cpe(app:"Foxit Reader", ver:FoxitVer[1], base:"cpe:/a:foxitsoftware:reader:", expr:"([0-9.]+)", regPort:0, insloc:binaryName, concluded:FoxitVer[0], regService:"ssh-login");
    break;
  }
}

ssh_close_connection();
exit(0);