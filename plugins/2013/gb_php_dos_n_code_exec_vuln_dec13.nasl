###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_dos_n_code_exec_vuln_dec13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PHP Remote Code Execution and Denial of Service Vulnerabilities - Dec13
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804174");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6420");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-19 18:09:47 +0530 (Thu, 19 Dec 2013)");
  script_name("PHP Remote Code Execution and Denial of Service Vulnerabilities - Dec13");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to remote code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.28 or 5.4.23 or 5.5.7 or later.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the 'asn1_time_to_time_t' function
  in 'ext/openssl/openssl.c' when parsing X.509 certificates.");

  script_tag(name:"affected", value:"PHP versions before 5.3.28, 5.4.x before 5.4.23, and 5.5.x before 5.5.7.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  or cause a denial of service (memory corruption).");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56055");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124436/PHP-openssl_x509_parse-Memory-Corruption.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.3.28") ||
   version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.22") ||
   version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.6")) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.28/5.4.23/5.5.7");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
