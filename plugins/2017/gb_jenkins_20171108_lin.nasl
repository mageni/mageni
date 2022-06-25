###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20171108_lin.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins Multiple Vulnerabilities Nov 17 (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112130");
  script_version("$Revision: 12761 $");

  script_cve_id("CVE-2017-1000391", "CVE-2017-1000392");

  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 10:05:00 +0100 (Tue, 07 Nov 2017)");
  script_name("Jenkins Multiple Vulnerabilities Nov 17 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-11-08/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - unsafe use of user names as directory names

  - a persisted XSS vulnerability in autocompletion suggestions");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
affect the integrity of the application.");

  script_tag(name:"affected", value:"Jenkins LTS 2.73.2 and prior, Jenkins weekly up to and including 2.88.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.89 or later / Jenkins LTS to 2.73.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.cloudbees.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.73.3" ) ) {
  vuln = TRUE;
  fix = "2.73.3";
}

if( version_in_range( version:vers, test_version:"2.74", test_version2:"2.88" ) ) {
  vuln = TRUE;
  fix = "2.89";
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
