###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_optionsbleed_version.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache HTTP Server OPTIONS Memory Leak Vulnerability (Optionsbleed)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108252");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-11 10:53:35 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2017-9798");
  script_bugtraq_id(100872);
  script_name("Apache HTTP Server OPTIONS Memory Leak Vulnerability (Optionsbleed)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/09/18/2");
  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100872");
  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/patches/apply_to_2.2.34/");
  script_xref(name:"URL", value:"https://www.apache.org/dist/httpd/CHANGES_2.4.28");

  script_tag(name:"summary", value:"Apache HTTP server allows remote attackers to read secret data
  from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf
  has certain misconfigurations, aka Optionsbleed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Optionsbleed is a use after free error in Apache HTTP server that
  causes a corrupted Allow header to be constructed in response to HTTP OPTIONS requests. This can leak
  pieces of arbitrary memory from the server process that may contain secrets. The memory pieces change
  after multiple requests, so for a vulnerable host an arbitrary number of memory chunks can be leaked.

  The bug appears if a webmaster tries to use the 'Limit' directive with an invalid HTTP method.

  Example .htaccess:

  <Limit abcxyz>
  </Limit>");

  script_tag(name:"impact", value:"The successful exploitation allows the attacker to read chunks of the
  host's memory.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x versions up to 2.2.34 and 2.4.x below 2.4.28.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.4.28. For Apache HTTP Server running
  version 2.2.34 apply the patch linked in the references.

  As a workaround the usage of .htaccess should be disabled competely via the 'AllowOverride None'
  directive within the webservers configuration. Furthermore all <Limit> statements within the
  webserver configuration needs to be verified for invalid HTTP methods.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.2.34" ) ) {
  vuln = TRUE;
  fix = "Apply the referenced patch or upgrade to 2.4.28";
}

if( vers =~ "^2\.4\." ) {
  if( version_is_less( version:vers, test_version:"2.4.28" ) ) {
    vuln = TRUE;
    fix = "2.4.28";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );