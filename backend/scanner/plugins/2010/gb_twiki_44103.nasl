###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_44103.nasl 12952 2019-01-07 06:54:36Z ckuersteiner $
#
# TWiki Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100857");
  script_version("$Revision: 12952 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 07:54:36 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-10-15 13:28:27 +0200 (Fri, 15 Oct 2010)");
  script_bugtraq_id(44103);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3841");

  script_name("TWiki Multiple Cross Site Scripting Vulnerabilities");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
 in the browser of an unsuspecting user in the context of the affected site. This may allow the
 attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to TWiki 5.0.1 are vulnerable.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
 information.");

  script_tag(name:"summary", value:"TWiki is prone to multiple cross-site scripting vulnerabilities
 because it fails to sufficiently sanitize user-supplied data.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44103");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2010-3841");
  script_xref(name:"URL", value:"http://twiki.org/");

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

url = dir + "/view?rev=%27%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E";

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",
                   extra_check:"TWiki",check_header:TRUE)) {
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
