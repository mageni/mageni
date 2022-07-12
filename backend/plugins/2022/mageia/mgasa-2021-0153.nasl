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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0153");
  script_cve_id("CVE-2019-12086", "CVE-2019-12384", "CVE-2019-12814", "CVE-2019-14379", "CVE-2019-14439", "CVE-2019-14540", "CVE-2019-16335", "CVE-2019-16942", "CVE-2019-16943", "CVE-2019-17267", "CVE-2019-17531", "CVE-2019-20330", "CVE-2020-10672", "CVE-2020-10673", "CVE-2020-10968", "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113", "CVE-2020-11619", "CVE-2020-11620", "CVE-2020-14060", "CVE-2020-14061", "CVE-2020-14062", "CVE-2020-14195", "CVE-2020-25649", "CVE-2020-35728", "CVE-2020-8840", "CVE-2020-9546", "CVE-2020-9547", "CVE-2020-9548", "CVE-2021-20190");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25266");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4452");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4542");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2030");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UKUALE2TUCKEKOHE2D342PQXN4MWCSLC/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4JYW4U272JPM7AYVNENNTWYYYAAQ4TZO/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2111");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2135");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2153");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2179");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:1523");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2406");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:4366");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-January/008253.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6X2UT4X6M7DLQYBOOHMXBWGYJ65RL2CT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind' package(s) announced via the MGASA-2021-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x
before 2.9.9. When Default Typing is enabled (either globally or for a specific
property) for an externally exposed JSON endpoint, the service has the
mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker
can host a crafted MySQL server reachable by the victim, an attacker can send
a crafted JSON message that allows them to read arbitrary local files on the
server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin
validation (CVE-2019-12086).

FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a
variety of impacts by leveraging failure to block the logback-core class from
polymorphic deserialization. Depending on the classpath content, remote code
execution may be possible (CVE-2019-12384).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x
through 2.9.9. When Default Typing is enabled (either globally or for a specific
property) for an externally exposed JSON endpoint and the service has JDOM
1.x or 2.x jar in the classpath, an attacker can send a specifically crafted
JSON message that allows them to read arbitrary local files on the server
(CVE-2019-12814).

SubTypeValidator.java in FasterXML jackson-databind before 2.9.9.2 mishandles
default typing when ehcache is used (because of
net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup),
leading to remote code execution (CVE-2019-14379).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x
before 2.9.9.2. This occurs when Default Typing is enabled (either globally or
for a specific property) for an externally exposed JSON endpoint and the
service has the logback jar in the classpath (CVE-2019-14439).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind before
2.9.10. It is related to com.zaxxer.hikari.HikariConfig (CVE-2019-14540).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind before
2.9.10. It is related to com.zaxxer.hikari.HikariDataSource. This is a different
vulnerability than CVE-2019-14540 (CVE-2019-16335).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0
through 2.9.10. When Default Typing is enabled (either globally or for a
specific property) for an externally exposed JSON endpoint and the service has
the commons-dbcp (1.4) jar in the classpath, and an attacker can find an RMI
service endpoint to access, it is possible to make the service execute a
malicious payload. This issue exists because of
org.apache.commons.dbcp.datasources.SharedPoolDataSource and
org.apache.commons.dbcp.datasources.PerUserPoolDataSource mishandling
(CVE-2019-16942).

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0
through 2.9.10. When Default Typing is enabled (either globally or for a
specific property) for an externally exposed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.9.8~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind-javadoc", rpm:"jackson-databind-javadoc~2.9.8~1.2.mga7", rls:"MAGEIA7"))) {
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
