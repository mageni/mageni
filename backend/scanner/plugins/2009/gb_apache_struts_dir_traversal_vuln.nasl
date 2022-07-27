###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_dir_traversal_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Apache Struts Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800271");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6505");
  script_bugtraq_id(32104);
  script_name("Apache Struts Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheStruts/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32497");
  script_xref(name:"URL", value:"http://struts.apache.org/2.x/docs/s2-004.html");
  script_xref(name:"URL", value:"http://issues.apache.org/struts/browse/WW-2779");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker launch directory traversal
  attack and gain sensitive information about the remote system directory contents.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.x and prior to 2.0.12
  Apache Struts version 2.1.x and prior to 2.1.3.");

  script_tag(name:"insight", value:"Input validation error within the user supplied request URI while read
  arbitrary files via '../' with a '/struts/' path which is related to
  FilterDispatcher and DefaultStaticContentLoader.");

  script_tag(name:"solution", value:"Upgrade to Apache Struts version 2.0.12, 2.1.3 or later.");

  script_tag(name:"summary", value:"This host is running Apache Struts and is prone to Directory Traversal
  Vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/struts/..%252f..%252f..%252fWEB-INF";

if( http_vuln_check( port:port, url:url, pattern:"classes", extra_check:make_list( "lib", "src" ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );