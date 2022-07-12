###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_40304.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PostgreSQL 'RESET ALL' Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100648");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-21 13:16:55 +0200 (Fri, 21 May 2010)");
  script_bugtraq_id(40304);
  script_cve_id("CVE-2010-1975");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_name("PostgreSQL 'RESET ALL' Unauthorized Access Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40304");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-8-4-4.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-8-2-17.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-8-1-21.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-8-3-11.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-8-0-25.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-7-4-29.html");

  script_tag(name:"summary", value:"PostgreSQL is prone to an unauthorized-access vulnerability.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to reset special parameter
  settings only a root user should be able to modify. This may aid in
  further attacks.");
  script_tag(name:"affected", value:"This issue affects versions prior to the following PostgreSQL
  versions:

  7.4.29

  8.0.25

  8.1.21

  8.2.17

  8.3.11

  8.4.4");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"8.4", test_version2:"8.4.3" )   ||
    version_in_range( version:vers, test_version:"8.3", test_version2:"8.3.10" )  ||
    version_in_range( version:vers, test_version:"8.2", test_version2:"8.2.16" )  ||
    version_in_range( version:vers, test_version:"8.1", test_version2:"8.1.20" )  ||
    version_in_range( version:vers, test_version:"8.0", test_version2:"8.0.24" )  ||
    version_in_range( version:vers, test_version:"7.4", test_version2:"7.4.28" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
