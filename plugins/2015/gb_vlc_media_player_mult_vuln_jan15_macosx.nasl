###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vuln_jan15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# VLC Media Player Multiple Vulnerabilities Jan15 (MAC OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805427");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9598", "CVE-2014-9597");
  script_bugtraq_id(72106, 72105);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_name("VLC Media Player Multiple Vulnerabilities Jan15 (MAC OS X)");

  script_tag(name:"summary", value:"The host is installed with VLC Media
  player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Flaws are due to:

  - Improper input sanitization by 'picture_Release' function in
    misc/picture.c.

  - Improper input sanitization by picture_pool_Delete function in
    misc/picture_pool.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.1.5 on
  MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player
  version 2.2.0-rc2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/72");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130004/");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:vlcVer, test_version:"2.1.5"))
{
  report = 'Installed version: ' + vlcVer + '\n' +
             'Fixed version:     ' + "2.2.0-rc2" + '\n';
  security_message(data:report );
  exit(0);
}
