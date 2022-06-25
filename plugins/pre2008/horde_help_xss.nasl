###############################################################################
# OpenVAS Vulnerability Test
# $Id: horde_help_xss.nasl 9981 2018-05-28 11:16:52Z ckuersteiner $
#
# Horde Help Subsystem XSS
#
# Authors:
# George A. Theall, <theall@tifaware.com>
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
###############################################################################

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15605");
  script_version("$Revision: 9981 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 13:16:52 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-2741");
  script_bugtraq_id(11546);

  script_name("Horde Help Subsystem XSS");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"solution", value:"Upgrade to Horde version 2.2.7 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Horde in which the help
subsystem is vulnerable to a cross site scripting attack since information passed to the help window is not
properly sanitized.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

# nb: if you change the URL, you probably need to change the pattern in the egrep() below.
url = dir + "/help.php?show=index&module=openvas%22%3E%3Cframe%20src=%22javascript:alert(42)%22%20";

if( http_vuln_check( port:port, url:url, pattern:'frame src="javascript:alert', check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
