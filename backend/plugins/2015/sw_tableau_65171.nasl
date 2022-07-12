###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_tableau_65171.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Tableau Server Unspecified SQL Injection Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = 'cpe:/a:tableausoftware:tableau_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111049");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-09 12:00:00 +0100 (Mon, 09 Nov 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(65171);
  script_cve_id("CVE-2014-1204");

  script_name("Tableau Server Unspecified SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_tableau_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tableau_server/installed");

  script_tag(name:"summary", value:"Tableau Server is prone to multiple SQL-injection vulnerabilities because
  it fails to sufficiently sanitize user-supplied data.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker can exploit these issues by manipulating the SQL query logic
  to carry out unauthorized actions on the underlying database.");
  script_tag(name:"affected", value:"Tableau Server prior to 8.0.7 and 8.1.2 are vulnerable.");
  script_tag(name:"solution", value:"The vendor has released updates.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65171");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31578");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"8.0.0", test_version2:"8.0.6" )
  || version_in_range( version:vers, test_version:"8.1.0", test_version2:"8.1.1" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "8.0.7/8.1.2" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
