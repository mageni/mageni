###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# OTRS Privilege Escalation Vulnerability
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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106863");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 10:56:38 +0700 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-9324");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker with agent permission is capable by opening a specific URL in a
browser to gain administrative privileges / full access. Afterward, all system settings can be read and changed.");

  script_tag(name:"affected", value:"OTRS 3.3.x up to and including 3.3.16, 4.0.x up to and including 4.0.23, 5.0.x up to and including 5.0.19.");

  script_tag(name:"solution", value:"Upgrade to OTRS 3.3.17, 4.0.24, 5.0.20 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-03-security-update-otrs-versions/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.3.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.24");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.20");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
