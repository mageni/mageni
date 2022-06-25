# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113677");
  script_version("2020-04-30T11:50:37+0000");
  script_tag(name:"last_modification", value:"2020-04-30 11:50:37 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-30 11:40:47 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-12284");

  script_name("FFmpeg <= 4.2.2 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"FFmpeg is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The heap-based buffer overflow vulnerability resides in
  cbs_jpeg_split_fragment in libavcodec/cbs_jpeg.c
  during JPEG_MARKER_SOS handling because of a missing length check.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on the target machine or crash the application.");

  script_tag(name:"affected", value:"FFmpeg through version 4.2.2.");

  script_tag(name:"solution", value:"No known solution is available as of 30th April, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=19734");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );