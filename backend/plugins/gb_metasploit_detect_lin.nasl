###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_metasploit_detect_lin.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Metasploit Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811588");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-08-30 17:46:40 +0530 (Wed, 30 Aug 2017)");
  script_name("Metasploit Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  Metasploit on Linux.

  The script logs in via ssh, searches for executable and queries the
  version from 'version.yml' file.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(!paths = find_file(file_name:"version.yml",file_path: '/', useregex:TRUE,
                  regexpar:"$", sock:sock)){
  exit(0);
}

foreach executableFile (paths)
{
  executableFile = chomp(executableFile);
  if("metasploit" >< executableFile)
  {
    metVer = get_bin_version(full_prog_name:"cat", version_argv:executableFile,
                             ver_pattern:'version: ([0-9.]+)', sock:sock);

    metUpdate = get_bin_version(full_prog_name:"cat", version_argv:executableFile,
                                ver_pattern:"revision: '([0-9]+)'", sock:sock);
    if(metVer[1] != NULL)
    {
      set_kb_item(name:"Metasploit/Linux/Ver", value:metVer[1]);
      if(metUpdate[1] != NULL){
        set_kb_item(name:"Metasploit/Linux/VerUpdate", value:metUpdate[1]);
      }

      cpe = build_cpe(value:metVer[1], exp:"^([0-9.]+)", base:"cpe:/a:rapid7:metasploit:");
      if(!cpe)
         cpe = "cpe:/a:rapid7:metasploit";

      register_product(cpe:cpe, location:executableFile);
      log_message(data: build_detection_report(app:"Metasploit",
                                               version: metVer[1],
                                               install: executableFile,
                                               cpe: cpe,
                                               concluded: metVer[1]));
      exit(0);
    }
  }
}
ssh_close_connection();
