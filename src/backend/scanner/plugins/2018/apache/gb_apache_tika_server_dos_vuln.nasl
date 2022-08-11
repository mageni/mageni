###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_dos_vuln.nasl 12884 2018-12-27 08:30:58Z asteins $
#
# Apache Tika Server < 1.20 Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112472");
  script_version("$Revision: 12884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-27 09:30:58 +0100 (Thu, 27 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-27 09:27:12 +0100 (Thu, 27 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-17197");
  script_bugtraq_id(106293);

  script_name("Apache Tika Server < 1.20 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  script_tag(name:"summary", value:"Apache Tika Server is prone to a denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A carefully crafted or corrupt sqlite file can cause an infinite loop.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the application to enter an infinite loop,
  resulting in denial-of-service conditions.");
  script_tag(name:"affected", value:"Apache Tika before version 1.20.");
  script_tag(name:"solution", value:"Update to version 1.20.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/7c021a4ea2037e52e74628e17e8e0e2acab1f447160edc8be0eae6d3@%3Cdev.tika.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:tika";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.20" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
