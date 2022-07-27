# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113425");
  script_version("2019-07-15T08:38:57+0000");
  script_tag(name:"last_modification", value:"2019-07-15 08:38:57 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-15 10:08:18 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13312", "CVE-2019-13390");
  script_bugtraq_id(109090);

  script_name("FFmpeg <= 4.1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"FFmpeg is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - block_cmp() in libavcodec/zmbvenc.c has a heap-based buffer over-read.

  - There is a division by zero at adx_write_trailer in libavformat/rawenc.c.
    This may be related to two NULL pointers passed as arguments
    at libavcodec/frame_thread_encoder.c.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to crash the application,
  read sensitive information or execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"FFmpeg versions 4.0.0 through 4.1.3.");
  script_tag(name:"solution", value:"Update to version 4.1.4.");

  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7980");
  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7979");
  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7981");
  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7982");
  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7983");
  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/7985");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
