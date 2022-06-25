###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mahara_bad_user_request_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Mahara <18.10.0 Mishandled User Requests Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112306");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-14 11:22:16 +0200 (Thu, 14 Jun 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1000141");

  script_name("Mahara <18.10.0 Mishandled User Requests Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"This host is running Mahara and is prone to a vulnerability dealing with mishandled user requests.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mahara mishandled user requests that could discontinue a user's ability to maintain their own account
  (changing username, changing primary email address, deleting account).

  The correct behavior was to either prompt them for their password and/or send a warning to their primary email address.");
  script_tag(name:"affected", value:"Mahara before version 18.10.0");
  script_tag(name:"solution", value:"Update Mahara to version 18.10.0 or above.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1422492");

  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "18.10.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.10.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
