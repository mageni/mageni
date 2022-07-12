###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_44050.nasl 13853 2019-02-25 14:54:56Z cfischer $
#
# Collabtive Cross Site Scripting and HTML Injection Vulnerabilities
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

CPE = "cpe:/a:collabtive:collabtive";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100855");
  script_version("$Revision: 13853 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 15:54:56 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-10-13 18:51:23 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-5284", "CVE-2010-5285");
  script_bugtraq_id(44050);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Collabtive Cross Site Scripting and HTML Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_collabtive_detect.nasl");
  script_mandatory_keys("collabtive/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44050");

  script_tag(name:"summary", value:"Collabtive is prone to multiple cross-site scripting vulnerabilities
  and an HTML-injection vulnerability because it fails to properly
  sanitize user-supplied input before using it in dynamically generated content.");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials or to control how the site is rendered to the user.
  Other attacks are also possible.");

  script_tag(name:"affected", value:"Collabtive 0.65 is vulnerable, prior versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vt_strings = get_vt_strings();
xss_string = vt_strings['random'];
url = string(dir, "/thumb.php?pic=%3Cscript%3Ealert(%27" + xss_string + "%27)%3C/script%3E");

if(http_vuln_check( port: port, url: url, pattern: "<script>alert\('" + xss_string + "'\)</script>", check_header: TRUE, extra_check: "file=" ) ) {
  report = report_vuln_url( port: port, url: url );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );