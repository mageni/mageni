###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_watchguard_fireware_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# WatchGuard Fireware XTM Multiple Vulnerabilities
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

CPE = 'cpe:/o:watchguard:fireware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106641");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 13:02:48 +0700 (Mon, 13 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-5387", "CVE-2016-5388", "CVE-2016-5386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WatchGuard Fireware XTM Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_snmp_os_detection.nasl", "gb_watchguard_fireware_detect.nasl");
  script_mandatory_keys("watchguard_fireware/installed");

  script_tag(name:"summary", value:"WatchGuard Fireware XMT Web UI is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WatchGuard Fireware XMT Web UI is prone to multiple vulnerabilities:

  - Cross-Site Request Forgery vulnerability on the Fireware Web UI login page.

  - Multiple vulnerabilities in the ighttpd component used by Fireware. (CVE-2016-5387, CVE-2106-5388, and
CVE-2016-5386)

  - Vulnerability in the Fireware Web UI that could allow an attacker to enumerate management user login IDs.");

  script_tag(name:"affected", value:"Version prior to 11.12.1.");

  script_tag(name:"solution", value:"Upgrade to version 11.12.1 or later");

  script_xref(name:"URL", value:"https://www.watchguard.com/support/release-notes/fireware/11/en-US/EN_ReleaseNotes_Fireware_11_12_1/index.html#Fireware/en-US/resolved_issues.html%3FTocPath%3D_____13");
  script_xref(name:"URL", value:"https://www.korelogic.com/Resources/Advisories/KL-001-2017-004.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
