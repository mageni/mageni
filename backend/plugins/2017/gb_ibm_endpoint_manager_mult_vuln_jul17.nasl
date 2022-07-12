##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_endpoint_manager_mult_vuln_jul17.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# IBM Tivoli Entpoint Manager Multiple Vulnerabilities July17
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.106979");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-21 15:30:52 +0700 (Fri, 21 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-1203",
"CVE-2017-1218", "CVE-2017-1219", "CVE-2017-1223", "CVE-2017-1224");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Tivoli Entpoint Manager Multiple Vulnerabilities July17");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");

  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"IBM Tivoli Endpoint Manager is prone to multiple vulnerabilities:

  - Multiple denial of service vulnerabilities in zlib. (CVE-2016-9840, CVE-2016-9841, CVE-2016-9842, CVE-2016-9842)

  - WebUI Component is vulnerable to cross-site scripting. (CVE-2017-1203)

  - WebUI Component is vulnerable to cross-site request forgery (CVE-2017-1218)

  - XML External Entity Injection (XXE) error when processing XML data (CVE-2017-1219)

  - Open redirect vulnerability (CVE-2017-1223)

  - WebUI Component uses weaker than expected cryptographic algorithms (CVE-2017-1224)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions 9.1, 9.2 and 9.5.");

  script_tag(name:"solution", value:"Follow the instructions in the referenced advisories.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22006014");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22005246");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^9\.1\.") {
  if (version_is_less(version: version, test_version: "9.1.1328.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.1.1328.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.2\.") {
  if (version_is_less(version: version, test_version: "9.2.11.19")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.2.11.19");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.5\.") {
  if (version_is_less(version: version, test_version: "9.5.6.63")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.5.6.63");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
