###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redis_buffer_overflow_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Redis 4.0.2 and prior Buffer Overflow vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113011");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-10 14:58:31 +0200 (Tue, 10 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  # There exists a backport of the vulnerable version for Debian Stretch
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15047");

  script_name("Redis 4.0.2 and prior Buffer Overflow vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_require_ports("Services/redis", 6379);
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Unchecked user input in cluster.c of redis server allows for a potential Buffer Overflow vulnerability.");
  script_tag(name:"vuldetect", value:"The scripts checks if the vulnerable version is present on the host.");
  script_tag(name:"insight", value:"The clusterLoadConfig function within /redis/src/cluster.c allows for a Buffer Overflow vulnerability leading from an array index being set from user-controllable input.");
  script_tag(name:"impact", value:"A successful exploitation would allow the attacker to corrupt the host's memory or even execute arbitrary commands on the host.");
  script_tag(name:"affected", value:"Redis Server version 4.0.2 and prior");
  script_tag(name:"solution", value:"Update to version 4.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/antirez/redis/issues/4278");

  exit(0);
}

CPE = "cpe:/a:redis:redis";

include( "host_details.inc" );
include( "version_func.inc" );

if( !port = get_app_port( cpe: CPE ) ) {
  exit( 0 );
}

if( !version = get_app_version( cpe: CPE, port: port ) ) {
  exit( 0 );
}

if( version_is_less_equal( version: version, test_version: "4.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
