###############################################################################
# OpenVAS Vulnerability Test
# $Id: squirrelmail_144.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# SquirrelMail < 1.4.4 XSS Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16228");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12337);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
  script_name("SquirrelMail < 1.4.4 XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name:"solution", value:"Upgrade to SquirrelMail 1.4.4 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of SquirrelMail whose
  version number suggests it is vulnerable to one or more cross-site
  scripting vulnerabilities :

  - Insufficient escaping of integer variables in webmail.php allows a
  remote attacker to include HTML / script into a SquirrelMail webpage
  (affects 1.4.0-RC1 - 1.4.4-RC1).

  - Insufficient checking of incoming URL vars in webmail.php allows an
  attacker to include arbitrary remote web pages in the SquirrelMail
  frameset (affects 1.4.0-RC1 - 1.4.4-RC1).

  - A recent change in prefs.php allows an attacker to provide a
  specially crafted URL that could include local code into the
  SquirrelMail code if and only if PHP's register_globals setting is
  enabled (affects 1.4.3-RC1 - 1.4.4-RC1).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );