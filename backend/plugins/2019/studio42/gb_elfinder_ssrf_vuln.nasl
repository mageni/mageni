###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elfinder_ssrf_vuln.nasl 13455 2019-02-05 07:38:02Z mmartin $
#
# elFinder < 2.1.46 SSRF Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112484");
  script_version("$Revision: 13455 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 08:38:02 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-15 12:26:12 +0100 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-6257");

  script_name("elFinder < 2.1.46 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to a server-side request forgery vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability occurs in get_remote_contents() in php/elFinder.class.php.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access the content of internal network resources.");
  script_tag(name:"affected", value:"elFinder through version 2.1.45.");
  script_tag(name:"solution", value:"Update to version 2.1.46.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/blob/68ec63c0aeca3963101aca8f842dc9f2e4c4c6d3/Changelog");
  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/commit/2f522db8f037a66ce9040ee0b216aa4a0359286c");

  exit(0);
}

CPE = "cpe:/a:studio42:elfinder";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.1.46" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.46" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
