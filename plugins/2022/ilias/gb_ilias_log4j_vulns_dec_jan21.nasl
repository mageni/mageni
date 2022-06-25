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

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117949");
  script_version("2022-01-28T10:15:13+0000");
  script_tag(name:"last_modification", value:"2022-01-28 11:09:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-28 09:13:52 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-24 18:30:00 +0000 (Mon, 24 Jan 2022)");

  script_cve_id("CVE-2019-17571", "CVE-2020-9488", "CVE-2020-9493", "CVE-2021-4104", "CVE-2022-23302",
                "CVE-2022-23305", "CVE-2022-23307");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.4.26, 6.x < 6.14, 7.x < 7.5 ilServer Multiple Log4j Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"The ilServer Java component of ILIAS is using a version of the
  Apache Log4j library which is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist in the Log4j library used by the
  ilServer component:

  - CVE-2019-17571 is a high severity issue targeting the SocketServer. Log4j includes a
  SocketServer that accepts serialized log events and deserializes them without verifying whether
  the objects are allowed or not. This can provide an attack vector that can be exploited.

  - CVE-2020-9488 is a moderate severity issue with the SMTPAppender. Improper validation of
  certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection
  to be intercepted by a man-in-the-middle attack which could leak any log messages sent through
  that appender.

  - CVE-2021-4104 is a high severity deserialization vulnerability in JMSAppender. JMSAppender uses
  JNDI in an unprotected manner allowing any application using the JMSAppender to be vulnerable if
  it is configured to reference an untrusted site or if the site referenced can be accesseed by the
  attacker. For example, the attacker can cause remote code execution by manipulating the data in
  the LDAP store.

  - CVE-2022-23302 is a high severity deserialization vulnerability in JMSSink. JMSSink uses JNDI in
  an unprotected manner allowing any application using the JMSSink to be vulnerable if it is
  configured to reference an untrusted site or if the site referenced can be accesseed by the
  attacker. For example, the attacker can cause remote code execution by manipulating the data in
  the LDAP store.

  - CVE-2022-23305 is a high severity SQL injection flaw in JDBCAppender that allows the data being
  logged to modify the behavior of the component. By design, the JDBCAppender in Log4j 1.2.x accepts
  an SQL statement as a configuration parameter where the values to be inserted are converters from
  PatternLayout. The message converter, %m, is likely to always be included. This allows attackers
  to manipulate the SQL by entering crafted strings into input fields or headers of an application
  that are logged allowing unintended SQL queries to be executed.

  - CVE-2022-23307 is a critical severity against the chainsaw component in Log4j 1.x. This is the
  same issue corrected in CVE-2020-9493 fixed in Chainsaw 2.1.0 but Chainsaw was included as part of
  Log4j 1.2.x.");

  script_tag(name:"affected", value:"The ilServer Java component in ILIAS versions prior to 5.4.26,
  6.x prior to 6.14 and 7.x prior to 7.5.");

  script_tag(name:"solution", value:"Update to version 5.4.26, 6.14, 7.5 or later.

  These releases updated the Log4j version used in the ilServer component from the end-of-life
  version 1.2.15 to 2.16.0 (for ILIAS version 6.14 and 7.5) or 2.17.0 (for ILIAS version 5.4.26).");

  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v5.4.25...v5.4.26");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_130116_35.html");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v6.13...v6.14");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_130117_35.html");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v7.4...v7.5");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_130115_35.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/5");
  script_xref(name:"URL", value:"https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/173yrzw9trfy6xdydfz05tsvp79z8rt7");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/LOG4J2-1863");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/1.2/");

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

if (version_is_less(version: version, test_version: "5.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
