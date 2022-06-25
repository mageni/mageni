###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_squirrelmail_csrf_vuln.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# SquirrelMail Multiple Cross-Site Request Forgery Vulnerabilities
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900830");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-28 14:39:11 +0200 (Fri, 28 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2964");
  script_name("SquirrelMail Multiple Cross-Site Request Forgery Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("squirrelmail/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34627");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52406");
  script_xref(name:"URL", value:"http://www.squirrelmail.org/security/issue/2009-08-12");

  script_tag(name:"impact", value:"Attacker may leverage this issue to modify user preferences, delete emails,
  and potentially send emails, and can hijack the authentication of unspecified victims.");

  script_tag(name:"affected", value:"SquirrelMail version 1.4.19 and prior on Linux.");

  script_tag(name:"insight", value:"Multiple CSRF errors are caused via features such as send message and change
  preferences, related to addrbook_search_html.php, folders_rename_getname.php, folders_rename_do.php,
  folders_subscribe.php, move_messages.php, options.php, options_highlight.php, options_identities.php,
  options_order.php, search.php, addressbook.php, compose.php, folders.php, folders_create.php, vcard.php and
  folders_delete.php in /src and mailbox_display.php in functions directory.");

  script_tag(name:"solution", value:"Upgrade to version 1.4.20 RC1 or later.");

  script_tag(name:"summary", value:"This host is running SquirrelMail and is prone to multiple Cross
  Site Request Forgery vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://squirrelmail.svn.sourceforge.net/viewvc/squirrelmail?view=rev&revision=13818");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.4.19" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.20 RC1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );