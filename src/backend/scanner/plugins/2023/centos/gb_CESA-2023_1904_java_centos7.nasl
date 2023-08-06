# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884287");
  script_version("2023-08-04T05:06:23+0000");
  script_cve_id("CVE-2023-21930", "CVE-2023-21937", "CVE-2023-21938", "CVE-2023-21939", "CVE-2023-21954", "CVE-2023-21967", "CVE-2023-21968");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-30 01:02:27 +0000 (Sun, 30 Jul 2023)");
  script_name("CentOS: Security Advisory for java (CESA-2023:1904)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:1904");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-July/086412.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2023:1904 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: improper connection handling during TLS handshake (8294474)
(CVE-2023-21930)

  * OpenJDK: Swing HTML parsing issue (8296832) (CVE-2023-21939)

  * OpenJDK: incorrect enqueue of references in garbage collector (8298191)
(CVE-2023-21954)

  * OpenJDK: certificate validation issue in TLS session negotiation
(8298310) (CVE-2023-21967)

  * OpenJDK: missing string checks for NULL characters (8296622)
(CVE-2023-21937)

  * OpenJDK: incorrect handling of NULL characters in ProcessBuilder
(8295304) (CVE-2023-21938)

  * OpenJDK: missing check for slash characters in URI-to-path conversion
(8298667) (CVE-2023-21968)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * Native code within the OpenJDK code base attempted to call close() on a
file descriptor repeatedly if it returned the error code, EINTR. However,
the close() native call is not restartable and this caused the virtual
machine to crash. The close() call is now only made once. (RHBZ#2159458)");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.372.b07~1.el7_9", rls:"CentOS7"))) {
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
