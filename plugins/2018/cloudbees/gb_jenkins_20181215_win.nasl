###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20181215_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins < 2.154 and < 2.138.4 LTS Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108512");
  script_version("$Revision: 12761 $");
  script_cve_id("CVE-2018-1000861", "CVE-2018-1000862", "CVE-2018-1000863", "CVE-2018-1000864");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-11 14:42:36 +0100 (Tue, 11 Dec 2018)");
  script_name("Jenkins < 2.154 and < 2.138.4 LTS Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-12-05/");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Code execution through crafted URLs (CVE-2018-1000861).

  - Forced migration of user records (CVE-2018-1000863).

  - Workspace browser allowed accessing files outside the workspace (CVE-2018-1000862).

  - Potential denial of service through cron expression form validation (CVE-2018-1000864).");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.138.3, Jenkins weekly up to and including 2.153.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.154 or later / Jenkins LTS to either 2.138.4 or 2.150.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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
  if ( version_is_less( version:vers, test_version:"2.138.4" ) ) {
    fix = "2.138.4/2.150.1";
  }
} else {
  if( version_is_less( version:vers, test_version:"2.154" ) ) {
    fix = "2.154";
  }
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );