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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0104");
  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0104)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0104");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0104.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22411");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2018:0095");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk, java-1.8.0-openjdk' package(s) announced via the MGASA-2018-0104 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in the Hotspot and AWT components of OpenJDK. An
untrusted Java application or applet could use these flaws to bypass certain
Java sandbox restrictions (CVE-2018-2582, CVE-2018-2641).

It was discovered that the LDAPCertStore class in the JNDI component of
OpenJDK failed to securely handle LDAP referrals. An attacker could possibly
use this flaw to make it fetch attacker controlled certificate data
(CVE-2018-2633).

The JGSS component of OpenJDK ignores the value of the
javax.security.auth.useSubjectCredsOnly property when using HTTP/SPNEGO
authentication and always uses global credentials. It was discovered that this
could cause global credentials to be unexpectedly used by an untrusted Java
application (CVE-2018-2634).

It was discovered that the JMX component of OpenJDK failed to properly set the
deserialization filter for the SingleEntryRegistry in certain cases. A remote
attacker could possibly use this flaw to bypass intended deserialization
restrictions (CVE-2018-2637).

It was discovered that the LDAP component of OpenJDK failed to properly encode
special characters in user names when adding them to an LDAP search query. A
remote attacker could possibly use this flaw to manipulate LDAP queries
performed by the LdapLoginModule class (CVE-2018-2588).

It was discovered that the DNS client implementation in the JNDI component of
OpenJDK did not use random source ports when sending out DNS queries. This
could make it easier for a remote attacker to spoof responses to those queries
(CVE-2018-2599).

It was discovered that the I18n component of OpenJDK could use an untrusted
search path when loading resource bundle classes. A local attacker could
possibly use this flaw to execute arbitrary code as another local user by
making their Java application load an attacker controlled class file
(CVE-2018-2602).

It was discovered that the Libraries component of OpenJDK failed to
sufficiently limit the amount of memory allocated when reading DER encoded
input. A remote attacker could possibly use this flaw to make a Java
application use an excessive amount of memory if it parsed attacker supplied
DER encoded input (CVE-2018-2603).

It was discovered that the key agreement implementations in the JCE component
of OpenJDK did not guarantee sufficient strength of used keys to adequately
protect generated shared secret. This could make it easier to break data
encryption by attacking key agreement rather than the encryption using the
negotiated secret (CVE-2018-2618).

It was discovered that the JGSS component of OpenJDK failed to properly handle
GSS context in the native GSS library wrapper in certain cases. A remote
attacker could possibly make a Java application using JGSS to use a previously
freed context (CVE-2018-2629).

It was discovered that multiple classes in the Libraries, AWT, and JNDI
components of OpenJDK did not sufficiently validate input ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk, java-1.8.0-openjdk' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.161~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.161~1.b14.1.mga6", rls:"MAGEIA6"))) {
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
