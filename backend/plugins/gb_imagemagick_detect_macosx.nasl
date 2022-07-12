###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_detect_macosx.nasl 13664 2019-02-14 11:13:52Z cfischer $
#
# ImageMagick Version Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810259");
  script_version("$Revision: 13664 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 12:13:52 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-12-21 19:01:05 +0530 (Wed, 21 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  ImageMagick on MAC OS X.

  The script logs in via ssh, searches for executable and queries the
  version from 'Magick-config' file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

magickFile = find_file(file_name:"Magick-config",file_path: "/opt", useregex:TRUE,
                           regexpar:"$", sock:sock);

foreach path (magickFile)
{
  path = chomp(path);

  magickVer = get_bin_version(full_prog_name:path, version_argv:"--version",
                              ver_pattern:"([0-9.]+\-?[0-9]{0,3})", sock:sock);

  if(magickVer[0] != NULL)
  {
    magickVer[0] = ereg_replace(pattern:"-", string:magickVer[0], replace: ".");

    set_kb_item(name: "ImageMagick/MacOSX/Version", value:magickVer[0]);

    register_and_report_cpe( app: "ImageMagick",
                             ver: magickVer[0],
                             concluded: magickVer[0],
                             base: "cpe:/a:imagemagick:imagemagick:",
                             expr: "^([0-9.]+)",
                             insloc: magickFile[0] );
    close(sock);
    exit(0);
  }
}

close(sock);
exit(0);