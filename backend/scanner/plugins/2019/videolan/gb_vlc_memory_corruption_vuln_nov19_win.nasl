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
  script_oid("1.3.6.1.4.1.25623.1.0.815724");
  script_version("2019-12-03T07:07:39+0000");
  script_cve_id("CVE-2019-18278");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-03 07:07:39 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-19 12:13:50 +0530 (Tue, 19 Nov 2019)");
  script_name("VLC Media Player Memory Corruption Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2019/10/random-bytes-in-vlc-308.html");

  script_tag(name:"summary", value:"The host is installed with VLC Media Player
  and is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'libqt' component
  when data from a faulting address controls code flow starting at
  'libqt_plugin!vlc_entry_license__3_0_0f+0x00000000003b9aba'");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers
  to cause denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"VLC Media Player version 3.0.8 on Windows");

  script_tag(name:"solution", value:"No known solution is available as of 19th November, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_equal(version:vers, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None Available", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
