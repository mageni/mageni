###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snort_detect_lin.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Snort Version Detection (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801138");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Snort Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Snort and
  sets the reuslt in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Snort Version Detection (Linux)";

snortSock = ssh_login_or_reuse_connection();
if(!snortSock){
  exit(0);
}

paths = find_bin(prog_name:"snort",sock:snortSock);
foreach binName (paths)
{
  snortVer = get_bin_version(full_prog_name:chomp(binName), version_argv:"-V",
                             ver_pattern:"> Snort! <", sock:snortSock);
  snortVer = eregmatch(pattern:"Version ([0-9.]+)( \(Build.?([0-9]+)\))?",
                       string:snortVer[1], icase:1);
  if(snortVer[1])
  {
    set_kb_item(name:"Snort/Linux/Ver", value:snortVer[1]);
    if(snortVer[3])
    {
      snortVer = snortVer[1] + "." + snortVer[3];
      set_kb_item(name:"Snort/Linux/Build", value:snortVer);
      log_message(data:"Snort version " + snortVer + " running at location "
                      + binName + " was detected on the host");

      cpe = build_cpe(value:snortVer, exp:"^([0-9.]+)", base:"cpe:/a:snort:snort:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
