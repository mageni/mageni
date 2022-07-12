##############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Multiple Vulnerabilities - Jun09
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
  script_oid("1.3.6.1.4.1.25623.1.0.800813");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0783", "CVE-2008-5515");
  script_bugtraq_id(35193, 35196);
  script_name("Apache Tomcat Multiple Vulnerabilities - Jun09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-4.html");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1022336");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1496");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=781708");

  script_tag(name:"impact", value:"Successful attempt could lead to remote code execution and attacker can gain
  the full permission on affected file, and can cause denial of service.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.0.0 to 6.0.18

  Apache Tomcat version 5.5.0 to 5.5.27

  Apache Tomcat version 4.1.0 to 4.1.39");

  script_tag(name:"insight", value:"Multiple flows are due to,

  - Error in 'XML parser' used for other web applications, which allows local users to
  read or modify the web.xml, context.xml, or tld files via a crafted application
  that is loaded earlier than the target application.

  - when FORM authentication is used, cause enumerate valid usernames via requests
  to /j_security_check with malformed URL encoding of passwords, related to
  improper error checking in the MemoryRealm, DataSourceRealm, and JDBCRealm
  authentication realms, as demonstrated by a % (percent) value for the j_password parameter.

  - when the 'Java AJP connector' and 'mod_jk load balancing' are used, via a
  crafted request with invalid headers, related to temporary blocking of
  connectors that have encountered errors, as demonstrated by an error
  involving a malformed HTTP Host header.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 4.1.40, or 5.5.28, or 6.0.20 or later.");

  script_tag(name:"summary", value:"This host is running Apache Tomcat Server and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"4.1.0", test_version2:"4.1.39" ) ||
    version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.27" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.1.40/5.5.28/6.0.20", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );