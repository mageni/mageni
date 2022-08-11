###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomcat_security_manager_bypass_vuln01_win.nasl 2016-02-25 11:25:47 +0530 Feb$
#
# Apache Tomcat Security Manager Bypass Vulnerability - 01 - Feb16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807408");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2016-0714", "CVE-2016-0706");
  script_bugtraq_id(83324, 83327);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-25 11:25:47 +0530 (Thu, 25 Feb 2016)");
  script_name("Apache Tomcat Security Manager Bypass Vulnerability - 01 - Feb16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to Security Manager Bypass Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation
  of several session persistence mechanisms and the StatusManagerServlet loaded
  by a web application when a security manager was configured.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  authenticated users to bypass intended SecurityManager restrictions and execute
  arbitrary code in a privileged context and read arbitrary HTTP requests, and
  consequently discover session ID values.");

  script_tag(name:"affected", value:"Apache Tomcat 6.0.0 before 6.0.45, and
  7.0.0 before 7.0.68, 8.0.0.RC1 before 8.0.31, and 9.0.0.M1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 6.0.45 or 7.0.68 or
  8.0.32 or 9.0.0.M3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( appPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:appPort, exit_no_version:TRUE ) )
  exit( 0 );

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^[6-9]\.")
{
  if(version_in_range(version:appVer, test_version:"6.0.0", test_version2:"6.0.44"))
  {
    fix = "6.0.45";
    VULN = TRUE;
  }

  if(version_in_range(version:appVer, test_version:"7.0.0", test_version2:"7.0.67"))
  {
    fix = "7.0.68";
    VULN = TRUE;
  }

  if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.30"))
  {
    fix = "8.0.32";
    VULN = TRUE;
  }

  if(version_is_equal(version:appVer, test_version:"9.0.0.M1"))
  {
    fix = "9.0.0.M3";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:appPort);
    exit(0);
  }
}
