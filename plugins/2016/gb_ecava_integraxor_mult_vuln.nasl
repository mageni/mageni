###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_mult_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# ECAVA IntegraXor Multiple Vulnerabilities
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

CPE = "cpe:/a:ecava:integraxor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106115");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 14:17:56 +0700 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2016-2299", "CVE-2016-2300", "CVE-2016-2301", "CVE-2016-2302", "CVE-2016-2303",
                "CVE-2016-2304", "CVE-2016-2305", "CVE-2016-2306");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ECAVA IntegraXor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_detect.nasl");
  script_mandatory_keys("EcavaIntegraXor/Installed");

  script_tag(name:"summary", value:"ECAVA IntegraXor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ECAVA IntegraXor is prone to multiple vulnerabilities:

SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands via unspecified vectors.
(CVE-2016-2299)

Remote attackers may bypass authentication and access unspecified web pages via unknown vectors. (CVE-2016-2300)

SQL injection vulnerability allows remote authenticated users to execute arbitrary SQL commands via unspecified
vectors. (CVE-2016-2301)

Remote attackers may obtain sensitive information by reading detailed error messages. (CVE-2016-2302)

CRLF injection vulnerability allows remote attackers to inject arbitrary HTTP headers and conduct HTTP response
splitting attacks via a crafted URL. (CVE-2016-2303)

ECAVA IntegraXor does not include the HTTPOnly flag in a Set-Cookie header for the session cookie, which makes
it easier for remote attackers to obtain potentially sensitive information via script access to this cookie.
(CVE-2016-2304)

Cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML via a
crafted URL. (CVE-2016-2305)

The HMI web server allows remote attackers to obtain sensitive cleartext information by sniffing the network.
(CVE-2016-2306)");

  script_tag(name:"impact", value:"The impact ranges from bypassing authentication to execute arbitrary
SQL commands.");

  script_tag(name:"affected", value:"Version 4.2.4502 and previous");

  script_tag(name:"solution", value:"Update to 5.0.4522 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jan/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if ( version_is_less_equal(version: version, test_version: "4.2.4502")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4522");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
