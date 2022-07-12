###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swftools_detect_lin.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# SWFTools Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801438");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SWFTools Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed SWFTools version and saves
  the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "SWFTools Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

swfName = find_file(file_name:"swfdump", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);

foreach binaryName (swfName)
{
  binaryName = chomp(binaryName);

  swfVer = get_bin_version(full_prog_name:binaryName, sock:sock,
                           version_argv:"-V",
                           ver_pattern:"swftools ([0-9.]+)");
  if(swfVer[1])
  {
    set_kb_item(name:"SWFTools/Ver", value:swfVer[1]);
    log_message(data:"SWFTools version " + swfVer[1] + " running at location "
                          + binaryName + " was detected on the host");

    cpe = build_cpe(value:swfVer[1], exp:"^([0-9.]+)", base:"cpe:/a:swftools:swftools:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
close(sock);
ssh_close_connection();
