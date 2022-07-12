###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikiwiki_ssh_detect.nasl 10451 2018-07-07 09:59:25Z cfischer $
#
# IkiWiki Detection (SSH)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800688");
  script_version("$Revision: 10451 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-07 11:59:25 +0200 (Sat, 07 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IkiWiki Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of IkiWiki and
  sets the specific KB entries.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
{
  exit(0);
}

ssh_port = get_ssh_port(default:22);

paths = find_bin(prog_name:"ikiwiki", sock:sock);
foreach ikiwikibin (paths)
{
  vers = get_bin_version(full_prog_name:chomp(ikiwikibin), sock:sock,
               version_argv:"--version", ver_pattern:"ikiwiki version ([0-9.]+)");

  if( vers[1] ) {
    set_kb_item(name:"ikiwiki/detected", value:TRUE);
    set_kb_item(name:"ikiwiki/ssh/detected", value:TRUE);

    version = vers[1];
    set_kb_item(name:"ikiwiki/ssh/" + ssh_port + "/concluded", value:vers[0]);
    set_kb_item(name:"ikiwiki/ssh/port", value:ssh_port);
    set_kb_item(name:"ikiwiki/ssh/" + ssh_port + "/version", value:version);
    set_kb_item(name:"ikiwiki/ssh/" + ssh_port + "/location", value:chomp(ikiwikibin));
    break;
  }
}
ssh_close_connection();

exit(0);
