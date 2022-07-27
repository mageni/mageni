###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpgroupware_sql_injection.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# PhpGroupWare multiple module SQL injection vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:phpgroupware:phpgroupware";

# Ref: PhpGroupWare Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14296");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9386);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0017");
  script_name("PhpGroupWare multiple module SQL injection vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpGroupWare/installed");

  script_xref(name:"URL", value:"http://www.phpgroupware.org/");

  script_tag(name:"solution", value:"Update to version 0.9.14.007 or newer");
  script_tag(name:"summary", value:"The remote host seems to be running PhpGroupWare, is a multi-user groupware
  suite written in PHP.

  It has been reported that this version may be prone to multiple SQL injection
  vulnerabilities  in the 'calendar' and 'infolog' modules.");
  script_tag(name:"insight", value:"The problems exist due to insufficient sanitization of user-supplied data.");
  script_tag(name:"impact", value:"A remote attacker may exploit these issues to influence SQL query logic to disclose
  sensitive information that could be used to gain unauthorized access.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ereg( pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-6][^0-9]))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.14.007" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );