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
  script_oid("1.3.6.1.4.1.25623.1.0.815204");
  script_version("2019-06-11T12:42:30+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-11 12:42:30 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 12:06:53 +0530 (Tue, 11 Jun 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Multiple Vulnerabilities Jun19 (Windows)");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An out of bounds write error in faad2 library.

  - Multiple out-of-band read errors.

  - Multiple heap overflow errors.

  - A NULL pointer dereference error.

  - Multiple use-after-free issues.

  - An integer underflow error.

  - Multiple integer overflow errors.

  - A division by zero error.

  - A floating point exception error.

  - An infinite loop error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the affected application, cause
  denial of service or launch other attacks.");

  script_tag(name:"affected", value:"VideoLAN VLC media player version 3.0.x before 3.0.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 3.0.7 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.videolan.org/developers/vlc-branch/NEWS");
  script_xref(name:"URL", value:"https://www.videolan.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vlcVer = infos['version'];
vlcpath = infos['location'];

if(version_in_range(version:vlcVer, test_version:"3.0.0", test_version2:"3.0.6"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.7", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}
exit(99);
