###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_detect_lin.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Mozilla Thunderbird Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800018");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla Thunderbird Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves Mozilla ThunderBird Version and
  saves it in KB.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Mozilla Thunderbird Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

birdName = find_file(file_name:"thunderbird", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);
foreach binary_birdName (birdName)
{
  binary_name = chomp(binary_birdName);
  birdVer = get_bin_version(full_prog_name:binary_name, version_argv:"-v",
                              ver_pattern:"[0-9].[0-9.]+", sock:sock);
  if(birdVer)
  {
    set_kb_item(name:"Thunderbird/Linux/Ver", value:birdVer[0]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);
    log_message(data:"Mozilla Thunderbird version " + birdVer[0] +
                  " running at location " + binary_birdName + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:birdVer[0], exp:"^([0-9.]+)", base:"cpe:/a:mozilla:thunderbird:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
