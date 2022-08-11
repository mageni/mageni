###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elfinder_inf_disc_vuln.nasl 13338 2019-01-29 07:44:39Z mmartin $
#
# elFinder <= 2.1.44 Information Disclosure Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.113324");
  script_version("$Revision: 13338 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 08:44:39 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-11 13:42:31 +0200 (Fri, 11 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5884");

  script_name("elFinder <= 2.1.44 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability affects installatons with the PHP curl extension enabled
  and safe_mode and open_basedir not set.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information.");
  script_tag(name:"affected", value:"elFinder through version 2.1.44.");
  script_tag(name:"solution", value:"Update to version 2.1.45.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/commit/f133163f2d754584de65d718b2fde96191557316");
  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/releases/tag/2.1.45");

  exit(0);
}

CPE = "cpe:/a:studio42:elfinder";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.1.45" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.45" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
