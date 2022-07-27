###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_detect_lin.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Mozilla Version Detection (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800884");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script is detects the installed version of Mozilla Browser
  and sets the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Mozilla Version Detection (Linux)";

mozilla_sock = ssh_login_or_reuse_connection();
if(!mozilla_sock){
  exit(0);
}

mozillaName = find_file(file_name:"mozilla", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:mozilla_sock);

foreach binary_name (mozillaName)
{
  binary_name = chomp(binary_name);
  mozillaVer = get_bin_version(full_prog_name:binary_name, sock:mozilla_sock,
                               version_argv:"-v", ver_pattern:"Mozilla " +
                               "([0-9]\.[0-9.]+)(.*build ([0-9]+))?");
  if(!isnull(mozillaVer[1]))
  {
    set_kb_item(name:"Mozilla/Linux/Ver", value:mozillaVer[1]);
    if(!isnull(mozillaVer[3]))
    {
      ver = mozillaVer[1] + "." + mozillaVer[3];
      set_kb_item(name:"Mozilla/Build/Linux/Ver", value:ver);
      log_message(data:"Mozilla version " + ver + " running at location " +
                        binary_name + " was detected on the host");

      cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:mozilla:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
