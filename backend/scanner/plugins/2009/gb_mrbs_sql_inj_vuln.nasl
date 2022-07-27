###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mrbs_sql_inj_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Meeting Room Booking System SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:john_beranek:meeting_room_booking_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800950");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3533");
  script_name("Meeting Room Booking System SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mrbs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MRBS/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35469");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51772");
  script_xref(name:"URL", value:"http://mrbs.sourceforge.net/view_text.php?section=NEWS&file=NEWS");

  script_tag(name:"impact", value:"Attackers can exploit this issue to inject arbitrary SQL code and modify
  information in the back-end database.");

  script_tag(name:"affected", value:"Meeting Room Booking System prior to 1.4.2 on all platforms.");

  script_tag(name:"insight", value:"The user supplied data passed into 'typematch' parameter in report.php is
  not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"Upgrade to Meeting Room Booking System 1.4.2 or later.");

  script_tag(name:"summary", value:"This host is installed with Meeting Room Booking System and is
  prone to a SQL Injection vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://mrbs.sourceforge.net/download.php");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );