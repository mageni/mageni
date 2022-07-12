##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_mult_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Horde Webmail Multiple Vulnerabilities
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

CPE = 'cpe:/a:horde:horde_groupware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106403");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-22 11:33:23 +0700 (Tue, 22 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Webmail Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Horde Webmail is prone to multiple vulnerabilities:

  - PHP script execution via CSRF attack.

  - Upload an SVG image file containing malicious Javascript code");

  script_tag(name:"impact", value:"An attacker may execute shell commands in the context of an admin or user.");

  script_tag(name:"affected", value:"Version 5.2.15 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2.16 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2789");
  script_xref(name:"URL", value:"https://lists.horde.org/archives/announce/2016/001197.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.16");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
