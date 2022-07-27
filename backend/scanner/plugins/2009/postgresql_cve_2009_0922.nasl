###############################################################################
# OpenVAS Vulnerability Test
# $Id: postgresql_cve_2009_0922.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PostgreSQL Conversion Encoding Remote Denial of Service
# Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100157");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_bugtraq_id(34090);
  script_cve_id("CVE-2009-0922");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("PostgreSQL Conversion Encoding Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34090");
  script_xref(name:"URL", value:"http://www.postgresql.org/");

  script_tag(name:"summary", value:"PostgreSQL is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue may allow attackers to terminate connections
  to the PostgreSQL server, denying service to legitimate users.");

  script_tag(name:"solution", value:"Updates are available. Update to newer Version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"8.3", test_version2:"8.3.6" )  ||
    version_in_range( version:vers, test_version:"8.2", test_version2:"8.2.6" )  ||
    version_in_range( version:vers, test_version:"8.1", test_version2:"8.1.11" ) ||
    version_in_range( version:vers, test_version:"8.0", test_version2:"8.0.17" ) ||
    version_in_range( version:vers, test_version:"7.4", test_version2:"7.4.19" ) ||
    version_in_range( version:vers, test_version:"7.3", test_version2:"7.3.21" ) ||
    version_in_range( version:vers, test_version:"7.2", test_version2:"7.2.7" )  ||
    version_in_range( version:vers, test_version:"7.1", test_version2:"7.1.3" )  ||
    version_in_range( version:vers, test_version:"7.0", test_version2:"7.0.3" )  ||
    version_in_range( version:vers, test_version:"6.5", test_version2:"6.5.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );