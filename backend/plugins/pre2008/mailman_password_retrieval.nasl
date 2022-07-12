###############################################################################
# OpenVAS Vulnerability Test
# $Id: mailman_password_retrieval.nasl 11723 2018-10-02 09:59:19Z ckuersteiner $
#
# Mailman Password Retrieval
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004-2005 George A. Theall
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

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12253");
  script_version("$Revision: 11723 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 11:59:19 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2004-0412");
  script_bugtraq_id(10412);

  script_name("Mailman Password Retrieval");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"The target is running version of the Mailman mailing list software that
  allows a list subscriber to retrieve the mailman password of any other subscriber");

  script_tag(name:"insight", value:"An attacker could exploit this issue by sending a specially crafted mail
  message to the server. Such a message sent via $listname-request@$target containing the lines :

  password address=$victim

  password address=$subscriber

  will return the password of both $victim and $subscriber for the list
  $listname@$target.");

  script_tag(name:"solution", value:"Upgrade to Mailman version 2.1.5 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = info['version'];
path = info['location'];

if( ereg( pattern:"^2\.1(b[2-6]|rc1|\.[1-4]$)", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.5", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
