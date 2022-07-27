###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_matrixssl_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MatrixSSL Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:peersec_networks:matrixssl";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106904");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 13:16:03 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-2780", "CVE-2017-2781", "CVE-2017-2782");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"MatrixSSL is prone multiple vulnerabilities.");

  script_tag(name:"insight", value:"MatrixSSL is prone multiple vulnerabilities:

  - x509 certificate SubjectDomainPolicy Remote Code Execution Vulnerability (CVE-2017-2780)

  - x509 certificate IssuerDomainPolicy Remote Code Execution Vulnerability (CVE-2017-2781)

  - x509 certificate General Names Information Disclosure Vulnerability (CVE-2017-2782)");

  script_tag(name:"affected", value:"MatrixSSL prior to version 3.9.3.");

  script_tag(name:"solution", value:"Update to version 3.9.3 or later.");

  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0276");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0277");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0278");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
