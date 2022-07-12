###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikiwiki_detect.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# ikiwiki Version Detection
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

tag_summary = "This script detects the installed version of ikiwiki and
  sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304287");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ikiwiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800688";
SCRIPT_DESC = "ikiwiki Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock)
{
  exit(0);
}

paths = find_bin(prog_name:"ikiwiki", sock:sock);
foreach ikiwikibin (paths)
{
  ikiwikiVer = get_bin_version(full_prog_name:chomp(ikiwikibin), sock:sock,
               version_argv:"--version", ver_pattern:"ikiwiki version ([0-9.]+)");
  if(ikiwikiVer[1] != NULL)
  {
    set_kb_item(name:"ikiwiki/Ver", value:ikiwikiVer[1]);
    log_message(data:"ikiwiki version " + ikiwikiVer[1] + " running at location "
                        + ikiwikibin + " was detected on the host");
    ssh_close_connection();
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ikiwikiVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ikiwiki:ikiwiki:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
