# Copyright (C) 2023 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0141");
  script_cve_id("CVE-2019-17571", "CVE-2021-4104", "CVE-2022-23302", "CVE-2022-23305");
  script_tag(name:"creation_date", value:"2023-04-17 04:13:02 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-17T10:09:22+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 16:08:00 +0000 (Thu, 27 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0141)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0141");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0141.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31708");
  script_xref(name:"URL", value:"https://github.com/mguessan/davmail/blob/master/RELEASE-NOTES.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'davmail' package(s) announced via the MGASA-2023-0141 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Included in Log4j 1.2 is a SocketServer class that is vulnerable to
deserialization of untrusted data which can be exploited to remotely
execute arbitrary code when combined with a deserialization gadget when
listening to untrusted network traffic for log data. This affects Log4j
versions up to 1.2 up to 1.2.17. (CVE-2019-17571)
JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted
data when the attacker has write access to the Log4j configuration. The
attacker can provide TopicBindingName and
TopicConnectionFactoryBindingName configurations causing JMSAppender to
perform JNDI requests that result in remote code execution in a similar
fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when
specifically configured to use JMSAppender, which is not the default.
(CVE-2021-4104)
JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of
untrusted data when the attacker has write access to the Log4j
configuration or if the configuration references an LDAP service the
attacker has access to. The attacker can provide a
TopicConnectionFactoryBindingName configuration causing JMSSink to perform
JNDI requests that result in remote code execution in a similar fashion to
CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically
configured to use JMSSink, which is not the default. (CVE-2022-23302)
By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a
configuration parameter where the values to be inserted are converters
from PatternLayout. The message converter, %m, is likely to always be
included. This allows attackers to manipulate the SQL by entering crafted
strings into input fields or headers of an application that are logged
allowing unintended SQL queries to be executed. Note this issue only
affects Log4j 1.x when specifically configured to use the JDBCAppender,
which is not the default. (CVE-2022-23305)");

  script_tag(name:"affected", value:"'davmail' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"davmail", rpm:"davmail~6.1.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
