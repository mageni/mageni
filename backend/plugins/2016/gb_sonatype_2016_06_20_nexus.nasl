###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonatype_2016_06_20_nexus.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Sonatype Nexus Repository Manager Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:sonatype:nexus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105819");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Sonatype Nexus Repository Manager Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.sonatype.org/advisories/archive/2016-06-20-Nexus/");

  script_tag(name:"impact", value:"The vulnerability allows for an unauthenticated attacker with network access to perform remote code exploits.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vulnerability is fixed in Nexus 2.11.2-01 and above.");
  script_tag(name:"summary", value:"A remote code execution has been discovered in Nexus Repository Manager.");
  script_tag(name:"affected", value:"All previous Nexus Repository Manager OSS/Pro versions up to and including 2.11.1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-21 12:28:37 +0200 (Thu, 21 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_sonatype_nexus_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("nexus/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less( version: vers, test_version: "2.11.2.01" ) )
  {
    report = report_fixed_ver( installed_version:vers, fixed_version:'2.11.2.01' );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
