###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln04_june15_lin.nasl 2015-06-17 16:00:15 Jun$
#
# PHP Multiple Vulnerabilities - 04 - Jun15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805658");
  script_version("$Revision: 12986 $");
  script_cve_id("CVE-2015-3330");
  script_bugtraq_id(74204);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 08:58:52 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-06-17 16:00:15 +0530 (Wed, 17 Jun 2015)");
  script_name("PHP Multiple Vulnerabilities - 04 - Jun15 (Linux)");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "apache/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to vulnerability in
  'php_handler' function in sapi/apache2handler/sapi_apache2.c script in PHP.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service or possibly execute arbitrary
  code via pipelined HTTP requests.");

  script_tag(name:"affected", value:"PHP versions before 5.4.40, 5.5.x before
  5.5.24, and 5.6.x before 5.6.8");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.40 or 5.5.24 or 5.6.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!apVer = get_app_version(cpe:CPE, port:port))
  exit(0);

if(apVer =~ "^2\.4\.") {

  CPE = "cpe:/a:php:php";

  if(!phpVer = get_app_version(cpe:CPE, port:port))
    exit(0);

  if(phpVer =~ "^5\.5\.") {
    if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.23")) {
      fix = "5.5.24";
      VULN = TRUE;
    }
  }

  if(phpVer =~ "^5\.6\.") {
    if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.7")) {
      fix = "5.6.8";
      VULN = TRUE;
    }
  }

  if(phpVer =~ "^5\.4\.") {
    if(version_is_less(version:phpVer, test_version:"5.4.40")) {
      fix = "5.4.40";
      VULN = TRUE;
    }
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);