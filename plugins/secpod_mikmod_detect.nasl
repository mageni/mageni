###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mikmod_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# MikMod Module Player Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900442");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MikMod Module Player Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the version of MikMod Module Player and sets
  result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "MikMod Module Player Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

mikmodPath = find_file(file_name:"mikmod", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach binary_mikmodName (mikmodPath)
{
  binary_name = chomp(binary_mikmodName);
  mikmodCmd = get_bin_version(full_prog_name:binary_name, version_argv:"--version",
                              ver_pattern:"MikMod ([0-9]\.[0-9.]+)", sock:sock);
  if(mikmodCmd[1] != NULL)
  {
    set_kb_item(name:"MikMod/Linux/Ver", value:mikmodCmd[1]);
    log_message(data:"MikMod Module Player version " + mikmodCmd[1] +
         " running at location " + binary_name + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:mikmodCmd[1], exp:"^([0-9.]+)", base:"cpe:/a:igno_saitz:libmikmod:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
