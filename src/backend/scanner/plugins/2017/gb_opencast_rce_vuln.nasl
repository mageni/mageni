###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencast_rce_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Opencast Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113061");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-06 14:32:33 +0100 (Wed, 06 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  # There are no backports of the affected versions
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1000217");

  script_name("Opencast Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast through version 2.3.2 is prone to a remote code execution vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable system is present on the target host.");
  script_tag(name:"insight", value:"Opencast allows for script injections through media and metadata in the player and medial module.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code on the target host.");
  script_tag(name:"affected", value:"Opencast through version 2.3.2");
  script_tag(name:"solution", value:"Update Opencast to version 2.3.3 or 3.0");

  script_xref(name:"URL", value:"https://groups.google.com/a/opencast.org/forum/#!topic/security-notices/sCpt0pIPEFg");

  exit(0);
}

CPE = "cpe:/a:opencast:opencast";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
