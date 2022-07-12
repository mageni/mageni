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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0120");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0120");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0120.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20711");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JWGDKQCJNISSJZ2DEPVCA3O6TAK2LBID/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4YXXBHMYBU6G4LLYCM72P57OMX6KLPUV/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TR5TUVVH3KU4VRKHKGH4DTM6PMAWWFSG/");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2017-1108.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'copy-jdk-configs, java-1.8.0-openjdk' package(s) announced via the MGASA-2017-0120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An untrusted library search path flaw was found in the JCE component of
OpenJDK. A local attacker could possibly use this flaw to cause a Java
application using JCE to load an attacker-controlled library and hence
escalate their privileges (CVE-2017-3511).

It was found that the JAXP component of OpenJDK failed to correctly
enforce parse tree size limits when parsing XML document. An attacker able
to make a Java application parse a specially crafted XML document could
use this flaw to make it consume an excessive amount of CPU and memory
(CVE-2017-3526).

It was discovered that the HTTP client implementation in the Networking
component of OpenJDK could cache and re-use an NTLM authenticated
connection in a different security context. A remote attacker could
possibly use this flaw to make a Java application perform HTTP requests
authenticated with credentials of a different user (CVE-2017-3509).

Note: This update adds support for the 'jdk.ntlm.cache' system property
which, when set to false, prevents caching of NTLM connections and
authentications and hence prevents this issue. However, caching remains
enabled by default.

It was discovered that the Security component of OpenJDK did not allow
users to restrict the set of algorithms allowed for Jar integrity
verification. This flaw could allow an attacker to modify content of the
Jar file that used weak signing key or hash algorithm (CVE-2017-3539).

Note: This updates extends the fix for CVE-2016-5542 released as part of
the MGASA-2016-0359 advisory to no longer allow the MD5 hash algorithm
during the Jar integrity verification by adding it to the
jdk.jar.disabledAlgorithms security property.

Newline injection flaws were discovered in FTP and SMTP client
implementations in the Networking component in OpenJDK. A remote attacker
could possibly use these flaws to manipulate FTP or SMTP connections
established by a Java application (CVE-2017-3533, CVE-2017-3544).");

  script_tag(name:"affected", value:"'copy-jdk-configs, java-1.8.0-openjdk' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"copy-jdk-configs", rpm:"copy-jdk-configs~2.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.131~1.b12.1.mga5", rls:"MAGEIA5"))) {
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
