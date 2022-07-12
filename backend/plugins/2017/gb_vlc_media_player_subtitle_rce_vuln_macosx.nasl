###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_subtitle_rce_vuln_macosx.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# VLC Media Player Subtitle Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811053");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2017-8313", "CVE-2017-8312", "CVE-2017-8311", "CVE-2017-8310");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-24 12:53:35 +0530 (Wed, 24 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player Subtitle Remote Code Execution Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the poor state of
  security in the way media player process subtitle files and the large number
  of subtitle formats. There are over 25 subtitle formats in use, each with unique
  features and capabilities. Media player often need to parse together multiple
  subtitle formats to ensure coverage and provide a better user experience. Like
  other, similar situations which involve fragmented software, this results in
  numerous distinct vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take complete control over any device running them.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 2.2.5.1
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player version
  2.2.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://blog.checkpoint.com/2017/05/23/hacked-in-translation");
  script_xref(name:"URL", value:"https://threatpost.com/subtitle-hack-leaves-200-million-vulnerable-to-remote-code-execution");
  script_xref(name:"URL", value:"http://www.videolan.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Based on blog from checkpoint solution is 2.2.5.1
if(version_is_less(version:vlcVer, test_version:"2.2.5.1"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.5.1");
  security_message(data:report);
  exit(0);
}
