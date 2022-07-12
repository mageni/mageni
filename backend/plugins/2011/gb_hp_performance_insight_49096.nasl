###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_performance_insight_49096.nasl 10772 2018-08-04 15:54:37Z cfischer $
#
# HP OpenView Performance Insight Security Bypass and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103200");
  script_version("$Revision: 10772 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-04 17:54:37 +0200 (Sat, 04 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-08-16 15:29:48 +0200 (Tue, 16 Aug 2011)");
  script_bugtraq_id(49096);
  script_cve_id("CVE-2011-2406", "CVE-2011-2407", "CVE-2011-2410");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("HP OpenView Performance Insight Security Bypass and HTML Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hp_performance_insight_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_openview_insight/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49096");
  script_xref(name:"URL", value:"https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-119^1211_4000_100");
  script_xref(name:"URL", value:"http://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c02942411&ac.admitted=1312903473487.876444892.199480143");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"HP OpenView Performance Insight is prone to a security-bypass
  vulnerability and an HTML-injection vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage the HTML-injection issue to inject hostile
  HTML and script code that would run in the context of the affected site, potentially allowing the
  attacker to steal cookie-based authentication credentials or to control how the site is rendered to
  the user.

  The attacker may leverage the security-bypass issue to bypass certain security restrictions and
  perform unauthorized actions in the affected application.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port( default:8080 );

if( ! dir = get_dir_from_kb( port:port, app:"hp_openview_insight" ) ) exit( 0 );
url = string( dir, "/jsp/sendEmail.jsp",'">',"<script>alert('openvas-xss-test')</script>" );

if( http_vuln_check( port:port, url:url, pattern:"<body bgcolor=.<script>alert\('openvas-xss-test'\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
