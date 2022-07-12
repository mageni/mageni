# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815254");
  script_version("2019-07-22T05:46:27+0000");
  script_cve_id("CVE-2019-13602");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-22 05:46:27 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-19 09:05:52 +0530 (Fri, 19 Jul 2019)");
  script_name("VLC Media Player Integer Underflow Vulnerability Jul19 (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://www.videolan.org/index.html");
  script_xref(name:"URL", value:"https://git.videolan.org/?p=vlc.git;a=commit;h=8e8e0d72447f8378244f5b4a3dcde036dbeb1491");
  script_xref(name:"URL", value:"https://git.videolan.org/?p=vlc.git;a=commit;h=b2b157076d9e94df34502dd8df0787deb940e938");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to an integer underflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer underflow
  issue in MP4_EIA608_Convert().");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  crash the application and launch further attacks using specially crafted files.");

  script_tag(name:"affected", value:"VideoLAN VLC media player version 3.0.7.1
  and earlier on Mac OS X.");

  script_tag(name:"solution", value:"No known solution is available as of 19th July, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vlcVer = infos['version'];
vlcpath = infos['location'];

if(version_is_less_equal(version:vlcVer, test_version:"3.0.7.1")) {
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"NoneAvailable", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}
exit(99);
