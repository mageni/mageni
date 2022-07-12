###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Multiple Security Bypass Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802415");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2011-1184", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_bugtraq_id(49762);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2012-01-16 15:35:35 +0530 (Mon, 16 Jan 2012)");
  script_name("Apache Tomcat Multiple Security Bypass Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1158180");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1159309");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1087655");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass intended
  access restrictions or gain sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat 5.5.x to 5.5.33, 6.x to 6.0.32 and 7.x to 7.0.11 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to errors in the HTTP Digest Access Authentication
  implementation,

  - which fails to check 'qop' and 'realm' values and allows to bypass
    access restrictions.

  - Catalina used as the hard-coded server secret in the
    DigestAuthenticator.java bypasses cryptographic protection mechanisms.

  - which fails to have the expected countermeasures against replay attacks.");

  script_tag(name:"summary", value:"The host is running Apache Tomcat Server and is prone to multiple
  security bypass vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade Apache Tomcat to 5.5.34, 6.0.33, 7.0.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.33" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.32" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.34/6.0.33/7.0.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
