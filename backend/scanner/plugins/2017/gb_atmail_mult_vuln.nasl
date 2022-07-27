##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atmail_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# atmail Multiple Vulnerabilities
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

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106861");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-09 16:32:29 +0700 (Fri, 09 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-9517", "CVE-2017-9518", "CVE-2017-9519", "CVE-2017-11617");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("atmail Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("atmail_detect.nasl");
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"atmail is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"atmail is prone to multiple vulnerabilities:

  - CSRF which allows an attacker to upload and import users via CSV

  - CSRF which allows an attacker can change SMTP hostname and hijack all emails

  - CSRF which allows an attacker create a user

  - XSS: send email with payload

  - It's been noted that login to user account via admin is being logged as USER LOGIN. The logs does not show that
login activity has been made by admin.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"atmail before 7.8.0.2.");

  script_tag(name:"solution", value:"Update to version 7.8.0.2 or later.");

  script_xref(name:"URL", value:"https://help.atmail.com/hc/en-us/articles/115007169147-Minor-Update-7-8-0-2-ActiveSync-2-3-6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.8.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
