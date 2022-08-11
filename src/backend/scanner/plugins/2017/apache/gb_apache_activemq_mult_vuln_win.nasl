###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_mult_vuln_win.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache ActiveMQ < 5.10.1 Multiple Security Vulnerabilities (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108290");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2014-3600", "CVE-2014-3612", "CVE-2014-8110", "CVE-2015-6524");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 10:54:29 +0100 (Tue, 07 Nov 2017)");
  script_name("Apache ActiveMQ < 5.10.1 Multiple Security Vulnerabilities (Windows)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.html");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ and is prone to
  multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to,

  - have unspecified impact via vectors involving an XPath based selector when dequeuing XML messages (CVE-2014-3600)

  - bypass authentication (CVE-2014-3612)

  - inject arbitrary web script or HTML via unspecified vectors (CVE-2014-8110)

  - obtain credentials via a brute force attack (CVE-2015-6524)");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - a XML external entity (XXE) vulnerability (CVE-2014-3600)

  - the LDAPLoginModule implementation in the Java Authentication and Authorization Service (JAAS)
  allowing logging in with an empty password and valid username, which triggers an unauthenticated bind.
  (CVE-2014-3612)

  - multiple cross-site scripting (XSS) vulnerabilities in the web based administration console (CVE-2014-8110)

  - the LDAPLoginModule implementation in the Java Authentication and Authorization Service (JAAS)
  allowing wildcard operators in usernames (CVE-2015-6524)");

  script_tag(name:"affected", value:"Apache ActiveMQ version before 5.10.1.");

  script_tag(name:"solution", value:"Update to Apache ActiveMQ version 5.10.1, or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.10.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.10.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );