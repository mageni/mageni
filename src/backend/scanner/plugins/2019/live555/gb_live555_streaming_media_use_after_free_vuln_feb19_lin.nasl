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
  script_oid("1.3.6.1.4.1.25623.1.0.113354");
  script_version("$Revision: 14139 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:03:19 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-13 11:45:16 +0200 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-7314");

  script_name("Live555 Streaming Media < 2019.02.03 Use-After-Free Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("os_detection.nasl", "gb_live555_detect.nasl");
  script_mandatory_keys("Host/runs_unixoide", "live555_streaming_media/installed");

  script_tag(name:"summary", value:"Live555 Streaming Media is prone to a Use-After-Free vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because Live555 Streaming Media mishandles the
  termination of an RTSP stream after RTP/RTCP-over-RTSP has been set up,
  which could lead to a Use-After-Free error.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the RTSP server.
  Other impact, such as code execution, may also be possible.");
  script_tag(name:"affected", value:"Live555 Streaming Media before version 2019.02.03.");
  script_tag(name:"solution", value:"Update to version 2019.02.03.");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00037.html");

  exit(0);
}

CPE = "cpe:/a:live555:streaming_media";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2019.02.03" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2019.02.03" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );