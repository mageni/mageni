# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112504");
  script_version("$Revision: 13752 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 10:00:49 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-29 15:22:12 +0100 (Tue, 29 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-6990", "CVE-2019-6991", "CVE-2019-6992", "CVE-2019-8423", "CVE-2019-8424",
  "CVE-2019-8425", "CVE-2019-8426", "CVE-2019-8427", "CVE-2019-8428", "CVE-2019-8429");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder <= 1.32.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS vulnerability in web/skins/classic/views/zones.php (CVE-2019-6990).

  - Stack-based buffer overflow in the zmLoadUser() function in zm_user.cpp of the zmu binary (CVE-2018-6991).

  - stored-self XSS vulnerability in web/skins/classic/views/controlcaps.php (CVE-2019-6992).

  - SQL Injection via the skins/classic/views/events.php filter[Query][terms][0][cnj] parameter (CVE-2019-8423).

  - SQL Injection via the ajax/status.php sort parameter (CVE-2019-8424).

  - XSS in the construction of SQL-ERR messages (CVE-2019-8425).

  - XSS via the newControl array, as demonstrated by the newControl[MinTiltRange] parameter (CVE-2019-8426).

  - Command injection via shell metacharacters (CVE-2019-8427).

  - SQL Injection via the skins/classic/views/control.php groupSql parameter, as demonstrated by a newGroup[MonitorIds][] value (CVE-2019-8428).

  - SQL Injection via the ajax/status.php filter[Query][terms][0][cnj] parameter (CVE-2019-8429).");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute code via a long username
  or execute HTML or JavaScript code via vulnerable fields.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the provided patches.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2444");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/a3e8fd4fd5b579865f35aac3b964bc78d5b7a94a");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2478");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/pull/2482");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/8c5687ca308e441742725e0aff9075779fa1a498");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2445");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2399");

  exit(0);
}

CPE = "cpe:/a:zoneminder:zoneminder";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less_equal(version: version, test_version: "1.32.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patches.");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
