###############################################################################
# OpenVAS Vulnerability Test
# $Id: imp_html_mime_viewer_xss.nasl 12156 2018-10-29 15:30:05Z mmartin $
#
# Horde IMP HTML MIME Viewer XSS Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2003-2004 George A. Theall
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

CPE = "cpe:/a:horde:imp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15393");
  script_version("$Revision: 12156 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 16:30:05 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Horde IMP HTML MIME Viewer XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003-2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("imp_detect.nasl");
  script_mandatory_keys("horde/imp/detected");

  script_xref(name:"URL", value:"http://lists.horde.org/archives/imp/Week-of-Mon-20040920/039246.html");

  script_tag(name:"solution", value:"Upgrade to Horde IMP version 3.2.6 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Horde IMP whose version number
  is between 3.0 and 3.2.5 inclusive.");

  script_tag(name:"insight", value:"Such versions are vulnerable to several XSS attacks when viewing HTML messages
  with the HTML MIME viewer and certain browsers.

  For additional information, see the referenced 3.2.6 release announcement.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = info['version'];
path = info['location'];

if( ereg( pattern:"^3\.(0|1|2|2\.[1-5])$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.6", install_path:path );
  security_message( port:port, data:report );
}

exit( 0 );
