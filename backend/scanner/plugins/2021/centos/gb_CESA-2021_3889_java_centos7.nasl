# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883393");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-35550", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35567", "CVE-2021-35578", "CVE-2021-35586", "CVE-2021-35588", "CVE-2021-35603");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:02:15 +0000 (Thu, 18 Nov 2021)");
  script_name("CentOS: Security Advisory for java (CESA-2021:3889)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:3889");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-November/048394.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2021:3889 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Loop in HttpsServer triggered during TLS session close (JSSE,
8254967) (CVE-2021-35565)

  * OpenJDK: Incorrect principal selection when using Kerberos Constrained
Delegation (Libraries, 8266689) (CVE-2021-35567)

  * OpenJDK: Weak ciphers preferred over stronger ones for TLS (JSSE,
8264210) (CVE-2021-35550)

  * OpenJDK: Excessive memory allocation in RTFParser (Swing, 8265167)
(CVE-2021-35556)

  * OpenJDK: Excessive memory allocation in RTFReader (Swing, 8265580)
(CVE-2021-35559)

  * OpenJDK: Excessive memory allocation in HashMap and HashSet (Utility,
8266097) (CVE-2021-35561)

  * OpenJDK: Certificates with end dates too far in the future can corrupt
keystore (Keytool, 8266137) (CVE-2021-35564)

  * OpenJDK: Unexpected exception raised during TLS handshake (JSSE, 8267729)
(CVE-2021-35578)

  * OpenJDK: Excessive memory allocation in BMPImageReader (ImageIO, 8267735)
(CVE-2021-35586)

  * OpenJDK: Incomplete validation of inner class references in
ClassFileParser (Hotspot, 8268071) (CVE-2021-35588)

  * OpenJDK: Non-constant comparison during TLS handshakes (JSSE, 8269618)
(CVE-2021-35603)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * A defensive security change in an earlier OpenJDK update led to a
performance degradation when using the Scanner class. This was due to the
change being applied to many common cases that did not need this
protection. With this update, we provide the original behaviour for these
cases. (RHBZ#1862929)");

  script_tag(name:"affected", value:"'java' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-accessibility-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-demo-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-devel-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-headless-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-javadoc-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-javadoc-zip-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-1.8.0.312.b07", rpm:"java-1.8.0-openjdk-src-1.8.0.312.b07~1.el7_9", rls:"CentOS7"))) {
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
