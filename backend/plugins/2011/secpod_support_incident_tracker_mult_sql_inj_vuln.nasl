##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_support_incident_tracker_mult_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Support Incident Tracker SiT! Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902703");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_bugtraq_id(48896);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Support Incident Tracker SiT! Multiple SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("support_incident_tracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sit/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518999");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103442/PT-2011-25.txt");

  script_tag(name:"insight", value:"The flaws are due to improper input validation in 'tasks.php',
  'report_marketing.php', 'search.php' and 'billable_incidents.php' scripts
  via various parameters before being used in a SQL query.");
  script_tag(name:"solution", value:"Upgrade to Support Incident Tracker SiT! version 3.64 or later.");
  script_tag(name:"summary", value:"This host is running Support Incident Tracker and is prone to SQL
  injection vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"Support Incident Tracker version prior 3.63p1 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://sitracker.org/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"3.63.p1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.64" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
