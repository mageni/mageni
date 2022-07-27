###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_35867.nasl 10459 2018-07-09 07:41:24Z cfischer $
#
# PHP Interruptions and Calltime Arbitrary Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100252");
  script_version("$Revision: 10459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 09:41:24 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-07-31 12:39:44 +0200 (Fri, 31 Jul 2009)");
  script_bugtraq_id(35867);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Interruptions and Calltime Arbitrary Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35867");
  script_xref(name:"URL", value:"http://www.php.net");
  script_xref(name:"URL", value:"http://www.blackhat.com/presentations/bh-usa-09/ESSER/BHUSA09-Esser-PostExploitationPHP-PAPER.pdf");

  script_tag(name:"impact", value:"Successful exploits will compromise the
  application and possibly the computer.");

  script_tag(name:"summary", value:"PHP is prone to a vulnerability that an attacker could exploit to
  execute arbitrary code with the privileges of the user running the
  affected application.");

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

if( version_is_less_equal( version:vers, test_version:"5.2.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );