##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_roundcube_file_disc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Roundcube Webmail File Disclosure Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112134");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-22 17:17:17 +0100 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16651");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail File Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/installed");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Roundcube Webmail allows unauthorized access to arbitrary files on the host's filesystem,
including configuration files. The attacker must be able to authenticate at the target system with a valid username/password
as the attack requires an active session.
The issue is related to file-based attachment plugins and _task=settings&_action=upload-display&_from=timezone requests.");

  script_tag(name:"affected", value:"Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3.");

  script_tag(name:"solution", value:"Update to version, 1.1.10, 1.2.7, 1.3.3 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2017/11/08/security-updates-1.3.3-1.2.7-and-1.1.10");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.3.0", test_version2: "1.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
