###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_detect_macosx.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Pidgin Version Detection (Mac OS X)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809872");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-20 15:36:08 +0530 (Fri, 20 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Pidgin Version Detection (Mac OS X)");
  script_tag(name:"summary", value:"Detects the installed version of
  Pidgin on MAC OS X.

  The script logs in via ssh, searches for folder 'pidgin' and queries the
  version from 'Changelog' file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

pidgin_file = find_file(file_name:"ChangeLog",file_path: "/usr/local/Cellar/pidgin/", useregex:TRUE,
                           regexpar:"$", sock:sock);

foreach path (pidgin_file)
{
  path = chomp(path);

  pidgin = get_bin_version(full_prog_name:"cat", version_argv:path,
                            ver_pattern:'pidgin', sock:sock);

  if(pidgin[0] != NULL)
  {
    pidgin_Ver = get_bin_version(full_prog_name:"cat", version_argv:path,
                                 ver_pattern:"version ([0-9.]+)", sock:sock);

    if(pidgin_Ver[1])
    {
      set_kb_item(name: "Pidgin/MacOSX/Version", value:pidgin_Ver[1]);

      cpe = build_cpe(value:pidgin_Ver[1], exp:"^([0-9.]+)", base:"cpe:/a:pidgin:pidgin:");
      if(isnull(cpe))
        cpe='cpe:/a:pidgin:pidgin';

      register_product(cpe:cpe, location:path);

      log_message(data: build_detection_report(app: "Pidgin",
                                               version: pidgin_Ver[1],
                                               install: path,
                                               cpe: cpe,
                                               concluded: pidgin_Ver[1]));
      exit(0);
    }
  }
}

close(sock);
exit(0);
