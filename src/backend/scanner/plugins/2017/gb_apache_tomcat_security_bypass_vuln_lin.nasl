###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_security_bypass_vuln_lin.nasl 73877 2017-07-07 11:25:47 +0530 March$
#
# Apache Tomcat Security Bypass Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811141");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2017-5664");
  script_bugtraq_id(98888);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-07 15:10:52 +0530 (Wed, 07 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error page mechanism of the Java Servlet
  Specification requires that, when an error occurs and an error page is
  configured for the error that occurred, the original request and response are
  forwarded to the error page. This means that the request is presented to the
  error page with the original HTTP method. If the error page is a static file,
  expected behaviour is to serve content of the file as if processing a GET request,
  regardless of the actual HTTP method. Tomcat's Default Servlet did not do this.
  Depending on the original request this could lead to unexpected and undesirable
  results for static error pages including, if the DefaultServlet is configured to
  permit writes, the replacement or removal of the custom error page");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  exploit this issue to bypass certain security restrictions and perform
  unauthorized actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"Apache Tomcat 9.0.0.M1 to 9.0.0.M20,
  Apache Tomcat 8.5.0 to 8.5.14,
  Apache Tomcat 8.0.0.RC1 to 8.0.43 and
  Apache Tomcat 7.0.0 to 7.0.77 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 9.0.0.M21, or 8.5.15,
  or 8.0.44, or 7.0.78 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/a42c48e37398d76334e17089e43ccab945238b8b7896538478d76066@%3Cannounce.tomcat.apache.org%3E");
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

if(appVer =~ "^[7-9]\.")
{
  if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.14")){
    fix = "8.5.15";
  }

  else if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.43")){
    fix = "8.0.44";
  }

  else if(version_in_range(version:appVer, test_version:"7.0", test_version2:"7.0.77")){
    fix = "7.0.78";
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M20")){
    fix = "9.0.0.M21";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:tomPort);
    exit(0);
  }
}
