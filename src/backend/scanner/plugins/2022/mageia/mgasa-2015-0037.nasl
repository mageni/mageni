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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0037");
  script_cve_id("CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0037");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0037.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15106");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152789#c82");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-0067.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the MGASA-2015-0037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated java-1.7.0 packages fix security vulnerabilities:

A flaw was found in the way the Hotspot component in OpenJDK verified
bytecode from the class files. An untrusted Java application or applet
could possibly use this flaw to bypass Java sandbox restrictions
(CVE-2014-6601).

Multiple improper permission check issues were discovered in the JAX-WS,
and RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions (CVE-2015-0412,
CVE-2015-0408).

A flaw was found in the way the Hotspot garbage collector handled phantom
references. An untrusted Java application or applet could use this flaw to
corrupt the Java Virtual Machine memory and, possibly, execute arbitrary
code, bypassing Java sandbox restrictions (CVE-2015-0395).

A flaw was found in the way the DER (Distinguished Encoding Rules) decoder
in the Security component in OpenJDK handled negative length values. A
specially crafted, DER-encoded input could cause a Java application to
enter an infinite loop when decoded (CVE-2015-0410).

It was discovered that the SSL/TLS implementation in the JSSE component in
OpenJDK failed to properly check whether the ChangeCipherSpec was received
during the SSL/TLS connection handshake. An MITM attacker could possibly
use this flaw to force a connection to be established without encryption
being enabled (CVE-2014-6593).

An information leak flaw was found in the Swing component in OpenJDK. An
untrusted Java application or applet could use this flaw to bypass certain
Java sandbox restrictions (CVE-2015-0407).

A NULL pointer dereference flaw was found in the MulticastSocket
implementation in the Libraries component of OpenJDK. An untrusted Java
application or applet could possibly use this flaw to bypass certain Java
sandbox restrictions (CVE-2014-6587).

Multiple boundary check flaws were found in the font parsing code in the 2D
component in OpenJDK. A specially crafted font file could allow an
untrusted Java application or applet to disclose portions of the Java
Virtual Machine memory (CVE-2014-6585, CVE-2014-6591).

Multiple insecure temporary file use issues were found in the way the
Hotspot component in OpenJDK created performance statistics and error log
files. A local attacker could possibly make a victim using OpenJDK
overwrite arbitrary files using a symlink attack (CVE-2015-0383).

Note: This update disables SSL 3.0 by default to mitigate the POODLE issue,
also known as CVE-2014-3566. The jdk.tls.disabledAlgorithms security
property can be used to re-enable SSL 3.0 support if needed. For additional
information, refer to the Red Hat Bugzilla bug linked to in the References
section.");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-accessibility", rpm:"java-1.7.0-openjdk-accessibility~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.75~2.5.4.1.mga4", rls:"MAGEIA4"))) {
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
