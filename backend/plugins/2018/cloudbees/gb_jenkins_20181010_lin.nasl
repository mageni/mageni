###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20181010_lin.nasl 13721 2019-02-18 07:47:09Z asteins $
#
# Jenkins < 2.146 and < 2.138.2 LTS Multiple Vulnerabilities (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108509");
  script_version("$Revision: 13721 $");
  script_cve_id("CVE-2018-1999043", "CVE-2018-1000406", "CVE-2018-1000407",
  "CVE-2018-1000408", "CVE-2018-1000409", "CVE-2018-1000410", "CVE-2018-1000997");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 08:47:09 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-11 14:42:36 +0100 (Tue, 11 Dec 2018)");
  script_name("Jenkins < 2.146 and < 2.138.2 LTS Multiple Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-10-10/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Path traversal vulnerability in Stapler allowed accessing internal data (CVE-2018-1000997).

  - Arbitrary file write vulnerability using file parameter definitions (CVE-2018-1000406).

  - Reflected XSS vulnerability (CVE-2018-1000407).

  - Ephemeral user record was created on some invalid authentication attempts (CVE-2018-1999043).

  - Ephemeral user record creation (CVE-2018-1000408).

  - Session fixation vulnerability on user signup (CVE-2018-1000409).

  - Failures to process form submission data could result in secrets being displayed or written to logs (CVE-2018-1000410).");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.138.1, Jenkins weekly up to and including 2.145.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.146 or later / Jenkins LTS to 2.138.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:jenkins:jenkins";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if ( version_is_less( version:vers, test_version:"2.138.2" ) ) {
    fix = "2.138.2";
  }
} else {
  if( version_is_less( version:vers, test_version:"2.146" ) ) {
    fix = "2.146";
  }
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
