##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_mult_sql_inj_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Open Ticket Request System (OTRS) Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902016");
  script_version("$Revision: 13960 $");
  script_cve_id("CVE-2010-0438");
  script_bugtraq_id(38146);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_name("Open Ticket Request System (OTRS) Multiple SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyrightopyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-01-en/");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-0438");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate SQL queries to
  read or modify records in the database, could also allow access to more
  administrator permissions.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to error in 'Kernel/System/Ticket.pm' in 'OTRS-Core'. It
  fails to sufficiently sanitize user-supplied data before using it in SQL queries.");
  script_tag(name:"solution", value:"Upgrade to Open Ticket Request System (OTRS) 2.1.9, 2.2.9, 2.3.5, 2.4.7");
  script_tag(name:"summary", value:"This host is running Open Ticket Request System (OTRS) and is prone to
  multiple SQL injection vulnerabilities.");
  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) version prior to 2.1.9, 2.2.9, 2.3.5 and 2.4.7");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://otrs.org/download/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.1.0", test_version2:"2.1.8" ) ||
    version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.8" ) ||
    version_in_range( version:vers, test_version:"2.3.0", test_version2:"2.3.4" ) ||
    version_in_range( version:vers, test_version:"2.4.0", test_version2:"2.4.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.9/2.2.9/2.3.5/2.4.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );