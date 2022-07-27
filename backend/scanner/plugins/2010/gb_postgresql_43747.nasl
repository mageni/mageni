###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_43747.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PostgreSQL PL/Perl and PL/Tcl Local Privilege Escalation Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100843");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_bugtraq_id(43747);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3433");
  script_name("PostgreSQL PL/Perl and PL/Tcl Local Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43747");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-1.html");
  script_xref(name:"URL", value:"http://www.postgresql.org");
  script_xref(name:"URL", value:"http://www.postgresql.org/support/security");

  script_tag(name:"summary", value:"PostgreSQL is prone to a local privilege-escalation vulnerability.");
  script_tag(name:"impact", value:"Exploiting this issue allows local attackers to gain elevated
  privileges and execute arbitrary commands with the privileges of the victim.");
  script_tag(name:"affected", value:"Versions prior to PostgreSQL 9.0.1 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"9.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );