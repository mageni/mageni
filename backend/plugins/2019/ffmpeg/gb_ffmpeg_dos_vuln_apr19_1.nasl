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
  script_oid("1.3.6.1.4.1.25623.1.0.113374");
  script_version("2019-04-24T12:07:47+0000");
  script_tag(name:"last_modification", value:"2019-04-24 12:07:47 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 13:53:23 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11338");
  script_bugtraq_id(108034);

  script_name("FFmpeg <= 4.1.2 Denial of Service (DoS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"FFmpeg is prone to a denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"libavcodec/hevcdec.c mishandles detection of duplicate first slices,
  which allows remote attackers to cause a NULL pointer dereference
  or an out-of-array access via crafted HVEC data.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a denial of service
  or possibly have other unspecified impact.");
  script_tag(name:"affected", value:"FFmpeg through version 4.1.2.");
  script_tag(name:"solution", value:"Update to version 4.1.3.");

  script_xref(name:"URL", value:"https://github.com/FFmpeg/FFmpeg/commit/54655623a82632e7624714d7b2a3e039dc5faa7e");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "4.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
