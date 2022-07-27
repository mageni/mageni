###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Partial HTTP Requests DoS Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802682");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2012-5568");
  script_bugtraq_id(56686);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2012-12-05 12:17:34 +0530 (Wed, 05 Dec 2012)");
  script_name("Apache Tomcat Partial HTTP Requests DoS Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=880011");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/11/26/2");
  script_xref(name:"URL", value:"http://captainholly.wordpress.com/2009/06/19/slowloris-vs-tomcat/");
  script_xref(name:"URL", value:"http://tomcat.10.n6.nabble.com/How-does-Tomcat-handle-a-slow-HTTP-DoS-tc2147776.html");
  script_xref(name:"URL", value:"http://tomcat.10.n6.nabble.com/How-does-Tomcat-handle-a-slow-HTTP-DoS-tc2147779.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Not_a_vulnerability_in_Tomcat");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  a denial of service conditions.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.0.x.");

  script_tag(name:"insight", value:"The flaw is caused by configuring an appropriate timeout using
  the connectionTimeout property for the relevant Connector(s) defined in server.xml.");

  script_tag(name:"summary", value:"The host is running Apache Tomcat Server and is prone to denial of
  service vulnerability. This NVT has been deprecated for the reasons explained by
  the Apache Tomcat team in the references.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat 7.0.52 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.33" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );