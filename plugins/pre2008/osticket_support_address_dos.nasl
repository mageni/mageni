###############################################################################
# OpenVAS Vulnerability Test
# $Id: osticket_support_address_dos.nasl 11958 2018-10-18 10:23:02Z cfischer $
#
# osTicket Support Address DoS
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) George A. Theall
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

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13859");
  script_version("$Revision: 11958 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:23:02 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("osTicket Support Address DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20060708122335/www.osticket.com/forums/showthread.php?t=301");

  script_tag(name:"solution", value:"Configure osTicket to receive mail using POP3.");

  script_tag(name:"summary", value:"The target is running at least one instance of osTicket 1.2.7 or
  earlier. Such versions are subject to a denial of service attack in open.php if osTicket is
  configured to receive mails using aliases.");

  script_tag(name:"impact", value:"If so, a remote attacker can generate a mail loop on the target
  by opening a ticket with the support address as the contact email address.");

  script_tag(name:"insight", value:"Please see the references for details.

  ***** The Scanner has determined the vulnerability exists on the target

  ***** simply by looking at the version number(s) of osTicket installed

  ***** there. It has no way of knowing which method osTicket uses to

  ***** retrieve mail.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port  = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( ereg( pattern:"^1\.(0|1|2|2\.[0-7])$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Mitigation", install_url:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
