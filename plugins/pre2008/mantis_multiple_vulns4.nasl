###################################################################
# OpenVAS Vulnerability Test
# $Id: mantis_multiple_vulns4.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# Mantis Multiple Flaws (4)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
###################################################################

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19473");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(14604);
  script_cve_id("CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mantis Multiple Flaws (4)");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112786017426276&w=2");

  script_tag(name:"solution", value:"Upgrade to Mantis 1.0.0rc2 or newer.");

  script_tag(name:"summary", value:"According to its banner, the version of Mantis on the remote host fails
  to sanitize user-supplied input to the 'g_db_type' parameter of the 'core/database_api.php' script.

  In addition, it is reportedly prone to multiple cross-site scripting issues.");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an attacker may
  be able to exploit this to connect to arbitrary databases as well as scan for arbitrary open ports, even on
  an internal network.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );
vers = info['version'];
path = info['location'];
if( path == "/" ) path = "";

# nb: request a bogus db driver.
url = path + "/core/database_api.php?g_db_type=vt-test";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
if( ! res ) exit( 0 );

# There's a problem if the requested driver file is missing.
# nb: this message occurs even with PHP's display_errors disabled.
if( "Missing file: " >< res && "/adodb/drivers/adodb-vt-test.inc.php" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_less( version:vers, test_version:"1.0.0rc2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0rc2", install_path:path );
  security_message( port:port, data:report );
}

exit( 0 );
