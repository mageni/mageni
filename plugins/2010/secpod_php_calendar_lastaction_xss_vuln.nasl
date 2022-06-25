###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_calendar_lastaction_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PHP-Calendar 'description' and 'lastaction' Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:php-calendar:php-calendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902190");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-2041");
  script_bugtraq_id(40334);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("PHP-Calendar 'description' and 'lastaction' Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_calendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PHP-Calendar/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33899");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1202");
  script_xref(name:"URL", value:"http://php-calendar.blogspot.com/2010/05/php-calendar-20-beta7.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511395/100/0/threaded");

  script_tag(name:"affected", value:"PHP-Calendar version 2.0 Beta6 and prior on all platforms.");
  script_tag(name:"insight", value:"The flaws are due to input validation errors when processing the
  'description' and 'lastaction' parameters.");
  script_tag(name:"solution", value:"Upgrade PHP-Calendar to 2.0 Beta7 or later.");
  script_tag(name:"summary", value:"This host is running PHP-Calendar and is prone to Cross Site
  Scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.0.beta6")){
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0 Beta7" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );