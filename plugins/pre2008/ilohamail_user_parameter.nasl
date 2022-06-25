##############################################################################
# OpenVAS Vulnerability Test
# $Id: ilohamail_user_parameter.nasl 10802 2018-08-07 08:55:29Z cfischer $
#
# IlohaMail User Parameter Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
##############################################################################

CPE = "cpe:/a:ilohamail:ilohamail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14637");
  script_version("$Revision: 10802 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 10:55:29 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9131);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("IlohaMail User Parameter Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("ilohamail_detect.nasl");
  script_mandatory_keys("ilohamail/detected");

  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=3589704&forum_id=27701");

  script_tag(name:"solution", value:"Upgrade to IlohaMail version 0.8.11 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of IlohaMail version
  0.8.10 or earlier. Such versions do not properly sanitize the 'user' parameter, which could allow a
  remote attacker to execute arbitrary code either on the target or in a victim's browser when a victim
  views a specially crafted message with an embedded image as long as PHP's magic quotes setting is
  turned off (it's on by default) and the MySQL backend is in use.

  See the reference for a discussion of this vulnerability.

  ***** The Scanner has determined the vulnerability exists on the target

  ***** simply by looking at the version number of IlohaMail

  ***** installed there.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port  = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit(0);
vers = infos['version'];
path = infos['location'];

if( vers =~ "^0\.([0-7].*|8\.([0-9]|10)(-Devel)?$)" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.8.11", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );