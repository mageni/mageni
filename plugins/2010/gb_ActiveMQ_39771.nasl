###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ActiveMQ_39771.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache ActiveMQ 'admin/queueBrowse' Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100613");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
  script_bugtraq_id(39771);
  script_name("Apache ActiveMQ 'admin/queueBrowse' Cross Site Scripting Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_activemq_detect.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("ActiveMQ/Web/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39771");
  script_xref(name:"URL", value:"https://issues.apache.org/activemq/browse/AMQ-2714");
  script_xref(name:"URL", value:"http://activemq.apache.org/");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a cross-site scripting vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"ActiveMQ 5.3.0 and 5.3.1 are affected. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection-NVT

url = string("/admin/queueBrowse/example.A?view=rss&feedType=%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E");

if( http_vuln_check( port:port, url:url, pattern:"Invalid feed type \[<script>alert\('vt-xss-test'\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );