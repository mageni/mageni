##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_check_mk_info_disc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Check_MK Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140449");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-24 14:59:40 +0700 (Tue, 24 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-14955");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check_MK Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Check_MK is prone to a race condition vulnerability which could lead to
information disclosure.");

  script_tag(name:"insight", value:"Check_MK mishandles certain errors within the failed-login save feature
because of a race condition, which allows remote attackers to obtain sensitive user information by reading a GUI
crash report.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Check_MK before version 1.2.8p26.");

  script_tag(name:"solution", value:"Update to version 1.2.8p26 or later.");

  script_xref(name:"URL", value:"https://www.rcesecurity.com/2017/10/cve-2017-14955-win-a-race-against-check-mk-to-dump-all-your-login-data/");
  script_xref(name:"URL", value:"https://mathias-kettner.de/check_mk_werks.php?werk_id=5208&HTML=yes");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.8p26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8p26");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
