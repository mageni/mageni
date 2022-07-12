###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20180509_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins < 2.121 and < 2.107.3 LTS Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112298");
  script_version("$Revision: 12761 $");
  script_cve_id("CVE-2018-1000192", "CVE-2018-1000193", "CVE-2018-1000194", "CVE-2018-1000195");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-06-07 12:00:00 +0200 (Thu, 07 Jun 2018)");
  script_name("Jenkins < 2.121 and < 2.107.3 LTS Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-05-09/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - An information exposure vulnerability in AboutJenkins.java, ListPluginsCommand.java that allows users with Overall/Read access to enumerate all installed plugins. (CVE-2018-1000192)

  - An improper neutralization of control sequences vulnerability in HudsonPrivateSecurityRealm.java that allows users to sign up using user names containing control characters
that can then appear to have the same name as other users, and cannot be deleted via the UI. (CVE-2018-1000193)

  - A path traversal vulnerability in FilePath.java, SoloFilePathFilter.java that allows malicious agents to read and write arbitrary
files on the Jenkins master, bypassing the agent-to-master security subsystem protection. (CVE-2018-1000194)

  - A server-side request forgery vulnerability in ZipExtractionInstaller.java that allows users with Overall/Read permission to have
Jenkins submit a HTTP GET request to an arbitrary URL and learn whether the response is successful (200) or not. (CVE-2018-1000195)");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.107.2, Jenkins weekly up to and including 2.120.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.121 or later / Jenkins LTS to 2.107.3 or
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
  if ( version_is_less( version:vers, test_version:"2.107.3" ) ) {
    vuln = TRUE;
    fix = "2.107.3";
  }
} else {
  if( version_is_less( version:vers, test_version:"2.121" ) ) {
    vuln = TRUE;
    fix = "2.121";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
