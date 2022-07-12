###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_observium_mult_vuln.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Observium Multiple Vulnerabilities
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

CPE = "cpe:/a:observium:network_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106389");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-15 10:22:35 +0700 (Tue, 15 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Observium Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_observium_detect.nasl");
  script_mandatory_keys("observium/installed");

  script_tag(name:"summary", value:"Observium is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Observium is prone to multiple vulnerabilities:

  - Deserialization of untrusted data: The issue can be exploited to write mostly user-controlled data to an
arbitrary file, such as a PHP session file. It is possible to exploit this issue to create a valid Observium
admin session.

  - Admins can inject shell commands, possibly as root

  - Incorrect use of cryptography in event feed authentication

  - Authenticated SQL injection: This can be exploited to leak various configuration details including the
password hashes of Observium users.");

  script_tag(name:"impact", value:"An attacker may create a valid admin session or obtain sensitive
information.");

  script_tag(name:"affected", value:"Observium before 0.16.10.8180");

  script_tag(name:"solution", value:"Update to 0.16.10.8180 or later");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Nov/59");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.16.10.8180")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.16.10.8180");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
