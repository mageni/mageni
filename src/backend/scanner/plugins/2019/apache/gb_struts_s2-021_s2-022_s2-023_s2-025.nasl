# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108629");
  script_version("2021-04-06T13:22:53+0000");
  script_bugtraq_id(67064, 67081, 76624, 76625);
  script_cve_id("CVE-2014-0112", "CVE-2014-0113", "CVE-2014-0116", "CVE-2014-7809", "CVE-2015-2992",
                "CVE-2015-5169");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-07 10:26:17 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-08-28 07:41:10 +0000 (Wed, 28 Aug 2019)");
  script_name("Apache Struts Multiple Vulnerabilities (S2-021, S2-022, S2-023, S2-025)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-021");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-022");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-023");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-025");
  script_xref(name:"Advisory-ID", value:"S2-021");
  script_xref(name:"Advisory-ID", value:"S2-022");
  script_xref(name:"Advisory-ID", value:"S2-023");
  script_xref(name:"Advisory-ID", value:"S2-025");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN88408929/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2015/JVNDB-2015-000124.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN95989300/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2015/JVNDB-2015-000125.html");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-0112, CVE-2014-0113: The excluded parameter pattern introduced in version
  2.3.16.1 to block access to getClass() method wasn't sufficient. It is possible to omit
  that with specially crafted requests. Also CookieInterceptor is vulnerable for the same
  kind of attack when it was configured to accept all cookies (when '*' is used to
  configure cookiesName param).

  - CVE-2014-0116: The excluded parameter pattern introduced in version 2.3.16.2 to block
  access to getClass() method didn't cover other cases and because of that attacker can
  change state of session, request and so on (when '*' is used to configure cookiesName
  param).

  - CVE-2014-7809: The attacker fetch any given form where a token is present and can
  predict the next value of the token used to secure form submission.

  - CVE-2015-2992, CVE-2015-5169: When the Struts2 debug mode is turned on, under certain
  conditions an arbitrary script may be executed in the 'Problem Report' screen. Also if
  JSP files are exposed to be accessed directly it's possible to execute an arbitrary
  script.");

  script_tag(name:"impact", value:"- CVE-2014-0112, CVE-2014-0113: A remote attacker can
  execute arbitrary Java code via crafted parameters.

  - CVE-2014-0116: Possibility to change internal state of session, request, etc.

  - CVE-2014-7809: The attacker make a specially craft form using the predicted token that
  force an action to a logged-in user (CSRF).

  - CVE-2015-2992, CVE-2015-5169: Affects of a cross-site scripting vulnerability when
  debug mode is switched on or JSPs are exposed in production environment.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.16.3.");

  script_tag(name:"solution", value:"Update to version 2.3.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if (version_in_range(version: vers, test_version: "2.0.0", test_version2: "2.3.16.3")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.3.20", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);