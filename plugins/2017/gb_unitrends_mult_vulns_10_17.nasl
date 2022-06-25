###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unitrends_mult_vulns_10_17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Unitrends Enterprise Backup 7.3.0 multiple vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113037");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-20 12:02:03 +0200 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3139", "CVE-2014-3008");
  script_bugtraq_id(66928);

  script_name("Unitrends Enterprise Backup 7.3.0 multiple vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_unitrends_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("unitrends/version");

  script_tag(name:"summary", value:"Multiple vulnerabilities in Unitrends Enterprise Backup version 7.3.0. Authentication bypass and remote code execution.");
  script_tag(name:"vuldetect", value:"Checks if the vulnerable version is present on the system.");
  script_tag(name:"insight", value:"Insufficient input sanitization leads to multiple vulnerabilities.");
  script_tag(name:"impact", value:"A successful exploit would allow the attacker to A) Bypass Authentication and B) Execute arbitrary commands on the host.");
  script_tag(name:"affected", value:"Unitrends Enterprise Backup version 7.3.0");
  script_tag(name:"solution", value:"Upgrade Unitrends Enterprise Backup to version 7.3.1");

  script_xref(name:"URL", value:"https://gist.github.com/brandonprry/10745756");

  exit(0);
}

CPE = 'cpe:/a:unitrends:enterprise_backup';

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_equal( version: version, test_version: "7.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
