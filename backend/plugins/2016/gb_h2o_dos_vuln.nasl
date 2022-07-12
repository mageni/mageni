###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_h2o_dos_vuln.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# H2O HTTP Server DoS Vulnerability
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

CPE = 'cpe:/a:h2o_project:h2o';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106488");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-23 14:52:16 +0700 (Fri, 23 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2016-7835");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("H2O HTTP Server DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_h2o_http_server_detect.nasl");
  script_mandatory_keys("h2o/installed");

  script_tag(name:"summary", value:"H2O HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability exists in H2O that can be used by a remote
attacker to execute DoS attacks or information theft");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may cause a DoS condition or obtain
arbitrary information which may include the server certificate's private keys, depending on the software's
settings.");

  script_tag(name:"affected", value:"H2O version 2.0.4, 2.1.0-beta3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.0.5, 2.1.0-beta4 or later.");

  script_xref(name:"URL", value:"https://github.com/h2o/h2o/issues/1144");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN44566208/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "2.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: check_vers, test_version: "2.1.0", test_version2: "2.1.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0-beta4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
