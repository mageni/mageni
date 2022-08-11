###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_av_detect_lin.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# AVG Anti-Virus Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Script modified by Sujit Ghosal (Date: 2009-05-27)
# NOTE: Patterns and variables used previously were wrong.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800394");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AVG Anti-Virus Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detect the installed version of AVG Anti-Virus and
  sets the result in KB.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

SCRIPT_DESC = "AVG Anti-Virus Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

avgPaths = find_file(file_name:"avgupdate", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);
foreach avgBin (avgPaths)
{
  filter = get_bin_version(full_prog_name:chomp(avgBin), sock:sock,
                           version_argv:"-v",
                           ver_pattern:"version:? ([0-9.]+)\.([0-9]+)[^.]?");

  # The below steps are carried out to append/increment build by one
  # (since it gets build version always reduced by one.
  if(filter[1] != NULL && filter[2] != NULL)
  {
    end = int(filter[2]) + 1;
    avgVer = filter[1] + "." + end;
    if(avgVer != NULL)
    {
      set_kb_item(name:"AVG/AV/Linux/Ver", value:avgVer);
      log_message(data:"AVG Anti-Virus version " + avgVer + " running at" +
                         " location " + avgBin +  " was detected on the host");
      ssh_close_connection();

      cpe = build_cpe(value: avgVer, exp:"^([0-9.]+)",base:"cpe:/a:avg:avg_anti-virus:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
ssh_close_connection();
