###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player LIVE555 RTSP Server code execution vulnerability (Mac OS X)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814316");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-4013");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-02 13:54:20 +0530 (Fri, 02 Nov 2018)");

  script_name("VLC Media Player LIVE555 RTSP Server code execution vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"This VT has been deprecated since VLC Media player is not affected.

  The host is installed with VLC Media Player
  and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the function that parses
  HTTP headers for tunneling RTSP over HTTP. An attacker may create a packet
  containing multiple 'Accept:' or 'x-sessioncookie' strings which could cause a
  stack buffer overflow in the function 'lookForHeader'");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a stack-based buffer overflow by sending a specially crafted packet,
  resulting in code execution.");

  script_tag(name:"affected", value:"VLC Media Player versions 3.0.4 and
  before on Mac OS X.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/10/vulnerability-spotlight-live-networks.html");
  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/");
  script_xref(name:"URL", value:"https://it.slashdot.org/comments.pl?sid=12787146&cid=57515512");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
VLCVer = infos['version'];
VLCpath = infos['location'];

if(version_is_less_equal(version:VLCVer, test_version:"3.0.4"))
{
  report = report_fixed_ver(installed_version:VLCVer, fixed_version:"None", install_path:VLCpath);
  security_message(data: report);
  exit(0);
}
