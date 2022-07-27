###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_37032.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability
#
# Authors:
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100352");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
  script_bugtraq_id(37032);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37032");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/70");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_exploitalert/14");
  script_xref(name:"URL", value:"http://www.php.net/");

  script_tag(name:"impact", value:"Successful exploits could allow an attacker to read and write files in
  unauthorized locations.");

  script_tag(name:"affected", value:"PHP 5.2.11 and 5.3.0 are vulnerable. Other versions may also be
  affected.");

  script_tag(name:"insight", value:"This vulnerability would be an issue in shared-hosting configurations
  where multiple users can create and execute arbitrary PHP script code.
  In such cases, 'open_basedir' restrictions are expected to isolate
  users from each other.");

  script_tag(name:"summary", value:"PHP is prone to an 'open_basedir' restriction-bypass vulnerability
  because of a design error.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"5.2.11" ) ||
    version_is_equal( version:vers, test_version:"5.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );