###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_detect_lin.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Tor Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) SecPod http://www.secpod.com
#
# Updated by Deepmala <kdeepmala@secpod.com>
# NOTE: Pattern used previously was not able to detect new version.
#
# Script Modified by Sharath S <sharaths@secpod.com> On 14th July 2009
# NOTE: Patterns and variables used previously were wrong.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900418");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"qod_type", value:"executable_version");

  script_name("Tor Version Detection (Linux)");
  script_tag(name:"summary", value:"Detects the installed version of Tor.

  The script logs in via ssh, searches for executable 'tor' and
  queries the found executables via command line option '--version'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

tor_sock = ssh_login_or_reuse_connection();
if(!tor_sock){
  exit(0);
}

torName = find_file(file_name:"tor", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:tor_sock);

foreach binaryName (torName)
{
  binaryName = chomp(binaryName);
  torVer = get_bin_version(full_prog_name:binaryName, sock:tor_sock,
                           version_argv:"--version",
                           ver_pattern:"Tor (v|version )([0-9.]+-?([a-z0-9]+)?)");
 if(torVer[2] != NULL)
  {
    set_kb_item(name:"Tor/Linux/Ver", value:torVer[2]);

    cpe = build_cpe(value: torVer[2], exp:"^([0-9.]+-?([a-z0-9]+)?)", base:"cpe:/a:tor:tor:");
    if(isnull(cpe))
      cpe = 'cpe:/a:tor:tor';

    register_product(cpe:cpe, location:binaryName);

    log_message(data:build_detection_report(app: "Tor",
                                             version: torVer[2],
                                             install: binaryName,
                                             cpe: cpe,
                                             concluded: torVer[2]));
  }
}
ssh_close_connection();
