###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flexera_installanywhere_detect_lin.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Flexera InstallAnywhere Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809016");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)");
  script_name("Flexera InstallAnywhere Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  Flexera InstallAnywhere on Linux.

  The script logs in via ssh, searches for executable and queries the
  version from 'config.json' file.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

sock = ssh_login_or_reuse_connection();

if(!sock){
  exit(0);
}

paths = find_file(file_name: "InstallAnywhere.lax",file_path: "/", useregex:TRUE,
                  regexpar:"$", sock:sock);

foreach path (paths)
{
  path = chomp(path);
  path_new = ereg_replace(pattern:" ", string:path, replace:"\ ");


  installVer = get_bin_version(full_prog_name:"cat", version_argv:path_new,
                               ver_pattern:'lax.version=([0-9.]+)', sock:sock);

  if(installVer[1] != NULL)
  {
    set_kb_item(name:"InstallAnywhere/Linux/Ver", value:installVer[1]);

    cpe = build_cpe(value:installVer[1], exp:"^([0-9.]+)", base:"cpe:/a:flexerasoftware:installanywhere:");
    if(!cpe)
      cpe = "cpe:/a:flexerasoftware:installanywhere";

    register_product(cpe:cpe, location:path);
    log_message(data: build_detection_report(app:"Flexera InstallAnywhere",
                                           version: installVer[1],
                                           install: path,
                                           cpe: cpe,
                                           concluded: installVer[1]));
    exit(0);
  }
}
close(sock);
