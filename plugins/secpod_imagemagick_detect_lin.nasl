##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_imagemagick_detect_lin.nasl 13664 2019-02-14 11:13:52Z cfischer $
#
# ImageMagick Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
# Revised to comply with Change Request #57.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.900563");
  script_version("$Revision: 13664 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 12:13:52 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  ImageMagick on Linux.

  The script logs in via ssh, searches for executable 'identify' and
  queries the found executables via command line option '-version'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

getPath = find_bin(prog_name:"identify", sock:sock);
foreach executableFile (getPath)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  imageVer = get_bin_version(full_prog_name:chomp(executableFile), version_argv:"-version",
                          ver_pattern:"ImageMagick ([0-9.]+\-?[0-9]{0,3})", sock:sock);

  if(imageVer[1] != NULL)
  {
    imageVer[1] = ereg_replace(pattern:"-", string:imageVer[1], replace: ".");
    set_kb_item(name:"ImageMagick/Lin/Ver", value:imageVer[1]);
    ssh_close_connection();

    register_and_report_cpe( app: "ImageMagick",
                             ver: imageVer[1],
                             concluded: imageVer[0],
                             base: "cpe:/a:imagemagick:imagemagick:",
                             expr: "^([0-9.]+)",
                             insloc: executableFile );

    exit(0);
  }
}

ssh_close_connection();