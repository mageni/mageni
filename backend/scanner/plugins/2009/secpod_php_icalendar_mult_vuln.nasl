###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_icalendar_mult_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Multiple Vulnerabilities in PHP iCalendar
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:phpicalendar:phpicalendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900199");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5967", "CVE-2008-5968");
  script_name("Multiple Vulnerabilities in PHP iCalendar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_icalendar_detect.nasl");
  script_mandatory_keys("PHP/iCalendar/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6519");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31944");

  script_tag(name:"impact", value:"Successful exploitation could result in Security Bypass or Directory
  Traversal attack on the affected web application.");

  script_tag(name:"insight", value:"- Error in admin/index.php file allows remote attackers to upload
  .ics file with arbitrary contents to the calendars/directory.

  - print.php file allows to include and execute arbitrary local files via
  a '../' in the cookie_language parameter in phpicalendar_* cookie.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PHP iCalendar and is prone to multiple
  vulnerabilities.");

  script_tag(name:"affected", value:"PHP iCalendar version 2.34 and prior on all running platform.

  Workaround:
  Restrict access to 'admin' area by adding security policies in '.htaccess'");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.34" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );