###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ffmpeg_detect_lin.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# FFmpeg Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800467");

  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FFmpeg Version Detection (Linux)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");

  script_family("Product detection");

  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of FFmpeg.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"ffmpeg", sock:sock);
foreach ffmpegbin (paths)
{
  ffmpegVer = get_bin_version(full_prog_name:chomp(ffmpegbin), sock:sock,
                              version_argv:"--version",
                              ver_pattern:"version ([0-9.]+)");
  if(ffmpegVer[1] != NULL)
  {
    set_kb_item(name:"FFmpeg/Linux/Ver", value:ffmpegVer[1]);
    ssh_close_connection();

    register_and_report_cpe(app:"FFmpeg", ver:ffmpegVer[1], base:"cpe:/a:ffmpeg:ffmpeg:", expr:"^([0-9.]+)", insloc:ffmpegbin);

    exit(0);
  }
}

ssh_close_connection();
