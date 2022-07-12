###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20180214_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins < 2.107 and < 2.89.4 LTS Multiple Vulnerabilities (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112228");
  script_version("$Revision: 12761 $");

  script_cve_id("CVE-2018-6356", "CVE-2018-1000067", "CVE-2018-1000068");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-02-19 11:00:00 +0100 (Mon, 19 Feb 2018)");
  script_name("Jenkins < 2.107 and < 2.89.4 LTS Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-02-14/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Path traversal vulnerability which allows access to files outside plugin resources. (CVE-2018-6356)

  - Improperly secured form validation for proxy configuration, allowing Server-Side Request Forgery. (CVE-2018-1000067)

  - Improper input validation, allowing unintended access to plugin resource files on case-insensitive file systems. (CVE-2018-1000068)");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.89.3, Jenkins weekly up to and including 2.106.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.107 or later / Jenkins LTS to 2.89.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.cloudbees.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if ( version_is_less( version:vers, test_version:"2.89.4" ) ) {
    vuln = TRUE;
    fix = "2.89.4";
  }
} else {
  if( version_is_less( version:vers, test_version:"2.107" ) ) {
    vuln = TRUE;
    fix = "2.107";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
