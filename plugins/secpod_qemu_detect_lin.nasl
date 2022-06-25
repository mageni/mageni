###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_qemu_detect_lin.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# QEMU Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-22
# Revised to comply with Change Request #57.
#
# Copyright:
# Copyright (c) SecPod http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900969");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-06T13:46:04+0000");
  script_tag(name:"last_modification", value:"2019-05-06 13:46:04 +0000 (Mon, 06 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("QEMU Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of QEMU.

  The script logs in via ssh, searches for executable 'qemu' and
  queries the found executables via command line option '-help'.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

qemuSock = ssh_login_or_reuse_connection();
if(!qemuSock){
  exit(0);
}

qemuName = find_file(file_name:"qemu", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:qemuSock);

found = FALSE;

foreach executableFile (qemuName)
{
  executableFile = chomp(executableFile);
  if(!executableFile) continue;
  qemuVer = get_bin_version(full_prog_name:executableFile, sock:qemuSock,
                            version_argv:"-help",
                            ver_pattern:"QEMU PC emulator version ([0-9.]+)");
  if(qemuVer[1] != NULL){
    set_kb_item(name:"QEMU/Lin/Ver", value:qemuVer[1]);

    cpe = build_cpe(value:qemuVer[1], exp:"^([0-9.]+)", base:"cpe:/a:qemu:qemu:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile, service:"ssh-login");

    report = build_detection_report(app:"QEMU PC emulator", version:qmuVer[1], install:executableFile, cpe:cpe, concluded:qemuVer[0]);
    log_message(data:report, port:0);
    found = TRUE;
  }
}

if(!found) {
  qemuName = find_file(file_name:"bin/qemu-.*", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:qemuSock);

  foreach executableFile (qemuName)
  {
    executableFile = chomp(executableFile);
    if(!executableFile) continue;
    file = eregmatch(pattern:'.*/([^/]+)', string:executableFile);
    file = file[1];
    qemuVer = get_bin_version(full_prog_name:executableFile, sock:qemuSock,
                              version_argv:"--version",
                              ver_pattern:"(" + file + "|QEMU emulator|QEMU PC emulator) version ([0-9.]+)");

    if(!isnull(qemuVer[2])){
      set_kb_item(name:"QEMU/Lin/Ver", value:qemuVer[2]);

      cpe = build_cpe(value:qemuVer[2], exp:"^([0-9.]+)", base:"cpe:/a:qemu:qemu:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:executableFile, service:"ssh-login");

      report = build_detection_report(app:"QEMU PC emulator", version:qemuVer[2], install:executableFile, cpe:cpe, concluded:qemuVer[0]);
      log_message(data:report, port:0);
      break;
    }
  }
}

ssh_close_connection();

exit( 0 );
