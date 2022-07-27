# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108741");
  script_version("2020-04-06T13:47:42+0000");
  script_cve_id("CVE-2020-11500");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-04-07 10:46:07 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 08:11:24 +0000 (Mon, 06 Apr 2020)");
  script_name("Zoom Client Insufficient Video and Audio Encryption - Apr20");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_detect_macosx.nasl", "gb_zoom_client_detect_win.nasl");
  script_mandatory_keys("zoom/client/detected");

  script_xref(name:"URL", value:"https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/");

  script_tag(name:"summary", value:"The Zoom Client is using insufficient video and audio encryption
  for Meetings.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Zoom Client for Meetings uses the ECB mode of AES for video and audio
  encryption. Within a meeting, all participants use a single 128-bit key.");

  script_tag(name:"affected", value:"All current Zoom Client versions are known to be affected.");

  script_tag(name:"solution", value:"No known solution is available as of 06th April, 2020. Information
  regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( get_kb_item( "zoom/client/mac/detected" ) )
  check = "4.6.919273.0402";
else if( get_kb_item( "zoom/client/win/detected" ) )
  check = "4.6.919253.0401";
else
  check = "3.5.374815.0324"; # nb: No detection for Linux available yet.

if( version_is_less_equal( version:vers, test_version:check ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
