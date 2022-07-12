##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_roundcube_pw_reset_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Roundcube Webmail Password Reset Vulnerability
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

CPE = 'cpe:/a:roundcube:webmail';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106804");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-15 13:21:35 +0700 (Mon, 15 May 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-8114");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail Password Reset Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/installed");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a arbitrary password reset vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the virtualmin and sasl drivers of the password plugin
allows authenticated users to reset arbitrary passwords.");

  script_tag(name:"affected", value:"Roundcube Webmail prior version 1.0.11, 1.1.x and 1.2.x.");

  script_tag(name:"solution", value:"Update to version, 1.0.11, 1.1.9, 1.2.5 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2017/04/28/security-updates-1.2.5-1.1.9-and-1.0.11");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1", test_version2: "1.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.2", test_version2: "1.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
