###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_dos_n_info_disc_vuln_lin.nasl 69688 2016-07-24 11:25:47 +0530 March$
#
# Apache Tomcat DoS and Information Disclosure Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810767");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2017-5650", "CVE-2017-5651");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-21 16:12:24 +0530 (Fri, 21 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat DoS and Information Disclosure Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to denial of service  and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- The handling of an HTTP/2 GOAWAY frame for a connection did not close
    streams associated with that connection that were currently waiting for
    a WINDOW_UPDATE before allowing the application to write more data

  - The refactoring of the HTTP connectors for 8.5.x onwards, introduced a
    regression in the send file processing. If the send file processing
    completed quickly, it was possible for the Processor to be added to the
    processor cache twice.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to consume all available processing threads and obtain sensitive
  information from requests other then their own.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0.M18 and
  Apache Tomcat versions 8.5.0 to 8.5.12 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 9.0.0.M19, 8.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/6694538826b87522fb723d2dcedd537e14ebe0a381d92e5525a531d8@%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/d24303fb095db072740d8154b0f0db3f2b8f67bc91a0562dbe89c738@%3Cannounce.tomcat.apache.org%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^[89]\.")
{
  if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.12"))
  {
    fix = "8.5.13";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M18"))
  {
    fix = "9.0.0.M19";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:tomPort);
    exit(0);
  }
}
