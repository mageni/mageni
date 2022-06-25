###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_matrixssl_mult_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# MatrixSSL Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106347");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-12 11:13:38 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-6890", "CVE-2016-6891", "CVE-2016-6892", "CVE-2016-6882", "CVE-2016-6883",
"CVE-2016-6884");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"MatrixSSL is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"MatrixSSL is prone to multiple vulnerabilities:

  - Heap-based Buffer Overflow: The Subject Alt Name field of X.509 certificates is not properly parsed. A
specially crafted certificate may result in a heap-based buffer overflow and arbitrary code execution.
(CVE-2016-6890)

  - Improper Restriction of Operations within the Bounds of a Memory Buffer: The ASN.1 Bit Field is not properly
parsed. A specially crafted certificate may lead to a denial of service condition due to an out of bounds read
in memory. (CVE-2016-6891)

  - Free of Memory not on the Heap: The x509FreeExtensions() function does not properly parse X.509 certificates.
A specially crafted certificate may cause a free operation on unallocated memory, resulting in a denial of
service condition. (CVE-2016-6892)");

  script_tag(name:"impact", value:"A remote, unauthenticated attacker may be able to create a denial of
service condition or execute arbitrary code in the context of the SSL stack.");

  script_tag(name:"affected", value:"MatrixSSL 3.8.5 and prior.");

  script_tag(name:"solution", value:"Update to version 3.8.6 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/396440");
  script_xref(name:"URL", value:"http://www.tripwire.com/state-of-security/security-data-protection/cyber-security/flawed-matrixssl-code-highlights-need-for-better-iot-update-practices/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
