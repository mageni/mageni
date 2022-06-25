###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_camera_dos_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# AXIS M1033-W IP Camera Denial of Service Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113151");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-06 13:37:37 +0200 (Fri, 06 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-9158");

  script_name("AXIS M1033-W IP Camera Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_network_cameras_ftp_detect.nasl");
  script_mandatory_keys("axis/camera/installed");

  script_tag(name:"summary", value:"An issue was discovered on AXIS M1033-W (IP camera) devices.
  They don't employ a suitable mechanism to prevent a DoS attack, which leads to a response time delay.
  An attacker can use the hping3 tool to perform an IPv4 flood attack, and the services are interrupted from attack start to end.");
  script_tag(name:"vuldetect", value:"The script checks if the target is a vulnerable device running a vulnerable firmware version.");
  script_tag(name:"affected", value:"Firmware before version 5.50.5.0");
  script_tag(name:"solution", value:"Update to firmware version 5.50.5.0 or above.");

  script_xref(name:"URL", value:"https://www.slideshare.net/secret/HpAEwK5qo5U4b1");
  script_xref(name:"URL", value:"https://www.axis.com/de-de/support/firmware");

  exit(0);
}

CPE = "cpe:/a:axis:network_camera";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

model = get_kb_item( "axis/camera/model" );

if( "M1033" >!< model ) exit( 0 );

if( version_is_less( version: version, test_version: "5.50.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.50.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
