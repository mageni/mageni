###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maildrop_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Maildrop Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800291");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Maildrop Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed Maildrop version and saves
  the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Maildrop Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

mailName = find_bin(prog_name:"maildrop", sock:sock);
foreach binary_mailName (mailName)
{
  mailVer = get_bin_version(full_prog_name:chomp(binary_mailName),
                            version_argv:"-version",
                            ver_pattern:"maildrop ([0-9.]+)", sock:sock);
  if(mailVer[1])
  {
    set_kb_item(name:"Maildrop/Linux/Ver", value:mailVer[1]);
    log_message(data:"Maildrop version " + mailVer[1] + " running at location "
                          + binary_mailName + " was detected on the host");

    cpe = build_cpe(value:mailVer[1], exp:"^([0-9.]+)", base:"cpe:/a:maildrop:maildrop:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
