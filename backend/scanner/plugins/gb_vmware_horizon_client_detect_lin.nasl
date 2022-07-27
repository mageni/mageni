###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_horizon_client_detect_lin.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# VMware Horizon Client Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813388");
  script_version("$Revision: 10890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-05 11:48:39 +0530 (Tue, 05 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Horizon Client Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  VMware Horizon Client.

  The script logs in via ssh, searches for executable 'vmware-view' and queries
  the found executables via command line option '--version'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

vm_sock = ssh_login_or_reuse_connection();
if(!vm_sock) exit( 0 );

paths = find_bin(prog_name:"vmware-view", sock:vm_sock);
foreach bin (paths)
{
  vmVer = get_bin_version(full_prog_name:chomp(bin), sock:vm_sock, version_argv:"--version",
                           ver_pattern:"VMware Horizon Client ([0-9.]+)");

  if(vmVer[1])
  {
    set_kb_item(name:"VMware/HorizonClient/Linux/Ver", value:vmVer[1]);

    cpe = build_cpe(value:vmVer[1], exp:"^([0-9.]+)", base:"cpe:/a:vmware:horizon_view_client:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:vmware:horizon_view_client";

    register_product( cpe:cpe, location:bin );

    log_message(data:build_detection_report(app:"VMware Horizon Client",
                                              version:vmVer[1],
                                              install:bin,
                                              cpe:cpe,
                                              concluded:vmVer[1]));
    close(vm_sock);
    exit(0);
  }
}
close(vm_sock);
exit(0);
