###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tiv_endpoint_manager_mult_vuln_feb17.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# IBM Tivoli Endpoint Manager Multiple Vulnerabilities Feb17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809886");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2016-0296", "CVE-2016-0297", "CVE-2016-0396", "CVE-2016-0214");
  script_bugtraq_id(94213, 94188, 94193, 94155);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-16 11:44:50 +0530 (Thu, 16 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager Multiple Vulnerabilities Feb17");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli
  Endpoint Manager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Enabling relay authentication(By default, unrestricted file upload on
    relays/servers with relay authentication is disabled).

  - Storage of potentially sensitive information in log files that could be
    available to a local user.

  - A missing HTTP Strict-Transport-Security Header through mitm.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to upload a malicious file, to obtain sensitive information, also to
  inject commands that would be executed with unnecessary higher privileges than
  expected.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  9.0, 9.1, 9.2, 9.5");

  script_tag(name:"solution", value:"Apply fixes from the reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993203");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993213");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993214");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993206");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");
  script_require_ports("Services/www", 52311);
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/endpoint-manager-family");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

if (version_is_less(version: tivVer, test_version: "9.1.1275.0")) {
  report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.1.1275.0");
  security_message(port: tivPort, data: report);
  exit(0);
}

if (tivVer =~ "^9\.2\.") {
  if (version_is_less(version: tivVer, test_version: "9.2.8.74")) {
    report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.2.8.74");
    security_message(port: tivPort, data: report);
    exit(0);
  }
}

if (tivVer =~ "^9\.5\.") {
  if (version_is_less(version: tivVer, test_version: "9.5.3.211")) {
    report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.5.3.211");
    security_message(port: tivPort, data: report);
    exit(0);
  }
}

exit(99);
