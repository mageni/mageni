###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ovaldi_detect_lin.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Ovaldi Version Detection (Linux)
#
# Authors:
# Arun Kallavi <Karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803368");
  script_version("$Revision: 10896 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-04-04 17:10:57 +0530 (Thu, 04 Apr 2013)");
  script_name("Ovaldi Version Detection (Linux)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Ovaldi.

The script logs in via ssh, searches for executable 'ovaldi' and
queries the found executables via command line option '-V'.");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

ovaldiSock = ssh_login_or_reuse_connection();
if(!ovaldiSock){
  exit(0);
}

path = find_bin(prog_name:"ovaldi",sock:ovaldiSock);
foreach binName (path)
{
  ovaldiVer = get_bin_version(full_prog_name:chomp(binName), version_argv:"-V",
              ver_pattern:"Version: ([0-9.]+).?(Build: ([0-9]+))?", sock:ovaldiSock);

  if(ovaldiVer[1] != NULL && ovaldiVer[3] != NULL){
    ver = ovaldiVer[1] + "." + ovaldiVer[3];
  }
  else if(ovaldiVer [1]!= NULL  && ovaldiVer[3] == NULL){
    ver = ovaldiVer[1];
  }

  if(ver)
  {
    set_kb_item(name:"Ovaldi/Linux/Version", value:ver);

    cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:mitre:ovaldi:");
    if(isnull(cpe))
      cpe = 'cpe:/a:mitre:ovaldi';

    register_product(cpe:cpe, location:binName);
    log_message(data: build_detection_report(app:"Ovaldi",
                                             version:ver,
                                             install:binName,
                                             cpe:cpe,
                                             concluded: ver));
  }
}
close(ovaldiSock);
ssh_close_connection();
