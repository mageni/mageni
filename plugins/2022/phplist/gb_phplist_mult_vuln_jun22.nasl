# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:phplist:phplist";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127042");
  script_version("2022-06-14T07:30:29+0000");
  script_tag(name:"last_modification", value:"2022-06-14 10:02:24 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-13 12:09:13 +0000 (Mon, 13 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-20029", "CVE-2017-20030", "CVE-2017-20031", "CVE-2017-20032",
                "CVE-2017-20033", "CVE-2017-20034", "CVE-2017-20035", "CVE-2017-20036");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpList <= 3.2.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phplist_detect.nasl");
  script_mandatory_keys("phplist/detected");

  script_tag(name:"summary", value:"phpList is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-20029: It is possible for an unauthenticated user to perform an SQL injection when
  updating the subscription information of an already subscribed user.

  - CVE-2017-20030: When sending a campaign, the sendformat parameter is vulnerable to SQL
  injection. The injection takes place into an UPDATE, so the easiest way to
  extract data is via error based SQL injection.

  - CVE-2017-20031: When viewing users, the sortby parameter can be used to sort the list. The drop
  down list allows sorting by email, dates, and so on. All non-word characters
  are removed, but there are no further checks.

  - CVE-2017-20032: When subscribing a user, metadata is saved in the database. When saving this
  data in the database, it is neither properly escaped nor are prepared
  statements used, but the input is HTML encoded.

  - CVE-2017-20033: This affects an unknown part of the file /lists/admin/. The manipulation of the
  argument page with the proper input leads to cross site scripting (Reflected).

  - CVE-2017-20034: The name of a list is echoed in various locations without encoding, leading to
  persistent XSS. An account with the privilege to create a list is required.

  - CVE-2017-20035: Various parameters of the subscribe page - such as the title - are vulnerable
  to persistent XSS. An account with the privilege to edit the subscribe page is
  required.

  - CVE-2017-20036: The expression parameter of bounce rules is vulnerable to persistent XSS. An
  account with the privilege to edit bounce rules is required.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpList version 3.2.6 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.1 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2017/Mar/45");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2017/Mar/46");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
