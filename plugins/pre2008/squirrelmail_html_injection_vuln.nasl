###############################################################################
# OpenVAS Vulnerability Test
# $Id: squirrelmail_html_injection_vuln.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# SquirrelMail From Email header HTML injection vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from George A. Theall <theall@tifaware.com>
# and Tenable Network Security
# modification by George A. Theall
# -change summary
# -remove references to global settings
# -clearer description
# -changed HTTP attack vector -> email
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

#  Credit: SquirrelMail Team

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14217");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10450);
  script_cve_id("CVE-2004-0639");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SquirrelMail From Email header HTML injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name:"solution", value:"Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
  sqimap_find_displayable_name in printMessageInfo in functions/mailbox_display.php with a call to htmlentities.");

  script_tag(name:"summary", value:"The target is running at least one instance of SquirrelMail whose
  version number is between 1.2.0 and 1.2.10 inclusive.");

  script_tag(name:"insight", value:"Such versions do not properly sanitize From headers, leaving users
  vulnerable to XSS attacks. Further, since SquirrelMail displays From headers when listing a folder,
  attacks does not require a user to actually open a message, only view the folder listing.

  For example, a remote attacker could effectively launch a DoS against
  a user by sending a message with a From header such as:

  From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx<semicolon> path=/'<semicolon></script><>

  which rewrites the session ID cookie and effectively logs the user out.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.2.0", test_version2:"1.2.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );