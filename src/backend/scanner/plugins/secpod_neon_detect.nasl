###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_neon_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# WebDAV Neon Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900827");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WebDAV Neon Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of WebDAV Neon and
  sets the reuslt in KB.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "WebDAV Neon Version Detection";

neon_sock = ssh_login_or_reuse_connection();
if(!neon_sock){
  exit(0);
}

paths = find_file(file_name:"neon-config", file_path:"/", useregex:TRUE,
                  regexpar:"$", sock:neon_sock);

foreach binName (paths)
{
  neonVer = get_bin_version(full_prog_name:chomp(binName), sock:neon_sock,
                            version_argv:"--version",
                            ver_pattern:"neon ([0-9]+\.[0-9]+\.[0-9]+)");

  if(neonVer[1] != NULL)
  {
    set_kb_item(name:"WebDAV/Neon/Ver", value:neonVer[1]);
    log_message(data:"WebDAV Neon version " + neonVer[1] +
                       " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:neonVer[1], exp:"^([0-9.]+)", base:"cpe:/a:webdav:neon:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
