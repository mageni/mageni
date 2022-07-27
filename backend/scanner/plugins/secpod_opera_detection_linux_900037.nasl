###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_detection_linux_900037.nasl 12733 2018-12-10 09:17:04Z cfischer $
#
# Opera Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900037");
  script_version("$Revision: 12733 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 10:17:04 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Opera Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Opera.

  The script logs in via ssh, searches for executable 'opera' and
  greps the version executable found.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Opera [0-9]\\+\\.[0-9]\\+");
garg[5] = string("Internal\\ build\\ [0-9]\\+");
garg[6] = string("Build\\ number:.*");
checkdupOpera = ""; # nb: To make openvas-nasl-lint happy...

operaName = find_file(file_name:"opera", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!operaName){
  ssh_close_connection();
  exit(0);
}

foreach binaryName(operaName){

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  operaVer = get_bin_version(full_prog_name:binaryName, version_argv:"-version", ver_pattern:"Opera ([0-9.]+) (Build ([0-9]+))?", sock:sock);

  if(operaVer && operaVer[1] && operaVer[3])
    operaBuildVer = operaVer[1] + "." + operaVer[3];

  if(operaVer && operaVer[1])
    operaVer = operaVer[1];

  if(!operaVer) {
    arg1 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;
    arg2 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[5] + raw_string(0x22) + " " + binaryName;
    arg3 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[6] + raw_string(0x22) + " " + binaryName;

    operaVer = get_bin_version(full_prog_name:"grep", version_argv:arg1, ver_pattern:"Opera ([0-9]+\.[0-9]+)", sock:sock);
    operaVer = operaVer[1];
  }

  if(operaVer){
    if(operaVer + ", ">< checkdupOpera)
      continue;

    checkdupOpera += operaVer + ", ";

    set_kb_item(name:"Opera/Linux/Version", value:operaVer);

    register_and_report_cpe(app:"Opera", ver:operaVer, base:"cpe:/a:opera:opera:", expr:"([0-9.]+)", regPort:0, insloc:binaryName, concluded:operaVer, regService:"ssh-login");

    if(!operaBuildVer){

      operaBuildVer = get_bin_version(full_prog_name:"grep", version_argv:arg2, ver_pattern:"Internal [B|b]uild ([0-9]+)", sock:sock);

      if(!operaBuildVer[1]){
        operaBuildVer = get_bin_version(full_prog_name:"grep", version_argv:arg3, ver_pattern:"Build number:.*", sock:sock);
        operaBuildVer = operaBuildVer[1] - raw_string(0x00);
        operaBuildVer = eregmatch(pattern:"Build number:([0-9]+)", string:operaBuildVer);
        if(operaBuildVer && operaBuildVer[1])
          operaBuildVer = operaVer + operaBuildVer[1];
      }
    }

    if(!isnull(operaBuildVer)){
      buildVer = operaBuildVer;
      set_kb_item(name:"Opera/Build/Linux/Ver", value:buildVer);
    }
  }
}

ssh_close_connection();
exit(0);