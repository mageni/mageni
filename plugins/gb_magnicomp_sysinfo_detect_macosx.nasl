###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magnicomp_sysinfo_detect_macosx.nasl 11789 2018-10-09 08:34:17Z santu $
#
# MagniComp SysInfo Version Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814051");
  script_version("$Revision: 11789 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 10:34:17 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-04 12:30:19 +0530 (Thu, 04 Oct 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MagniComp SysInfo Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  MagniComp SysInfo Version on MAC OS X.

  The script logs in via ssh, searches for configuration file 'configvars.cfg'
  and queries the file for string 'ProdVersionFull'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_xref(name:"URL", value:"https://www.magnicomp.com");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_file(file_name:"configvars.cfg",file_path: "/opt", useregex:TRUE,
                    regexpar:"$", sock:sock);
foreach binName (paths)
{
  magnicnf = get_bin_version(full_prog_name:"cat", sock:sock, version_argv:binName, ver_pattern:'IsMagniComp="yes');
  if(!magnicnf) break;

  sysinfoVer = get_bin_version(full_prog_name:"cat", version_argv:binName,
                              ver_pattern:'ProdVersionFull="([0-9A-Z. ]+)', sock:sock);
  if(sysinfoVer[1] != NULL)
  {
    sysinfoVer = sysinfoVer[1];
    set_kb_item(name:"MagniComp/SysInfo/Macosx/Ver", value:sysinfoVer);

    cpe = build_cpe(value:sysinfoVer, exp:"^([0-9A-Z.]+)", base:"cpe:/a:magnicomp:sysinfo:");
    if(isnull(cpe))
      cpe='cpe:/a:magnicomp:sysinfo';

    register_product(cpe:cpe, location:'/opt/sysinfo');

    log_message(data: build_detection_report(app:"MagniComp SysInfo",
                                             version:sysinfoVer,
                                             install:"/opt/sysinfo",
                                             cpe:cpe,
                                             concluded:sysinfoVer));
    exit(0);
  }
}
ssh_close_connection();
exit(0);
