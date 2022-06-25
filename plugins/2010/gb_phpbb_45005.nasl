###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbb_45005.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# phpBB 'includes/message_parser.php' HTML Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100922");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:57:59 +0100 (Tue, 30 Nov 2010)");
  script_bugtraq_id(45005);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("phpBB 'includes/message_parser.php' HTML Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45005");
  script_xref(name:"URL", value:"http://www.phpbb.com/");
  script_xref(name:"URL", value:"http://www.phpbb.com/support/documents.php?mode=changelog&version=3#v307-PL1");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials, control how the site is rendered to the user, or launch
  other attacks.");

  script_tag(name:"affected", value:"Versions prior to phpBB 3.0.8 are vulnerable.");

  script_tag(name:"solution", value:"The vendor has released updates. Please contact the vendor for
  details.");

  script_tag(name:"summary", value:"phpBB is prone to an HTML-injection vulnerability because it fails to
  properly sanitize user-supplied input.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.0.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );