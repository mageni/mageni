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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4290.1");
  script_cve_id("CVE-2022-21618", "CVE-2022-21619", "CVE-2022-21624", "CVE-2022-21626", "CVE-2022-21628", "CVE-2022-39399");
  script_tag(name:"creation_date", value:"2022-11-30 04:20:10 +0000 (Wed, 30 Nov 2022)");
  script_version("2022-11-30T10:12:07+0000");
  script_tag(name:"last_modification", value:"2022-11-30 10:12:07 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 21:18:00 +0000 (Tue, 18 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4290-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224290-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2022:4290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

CVE-2022-21626: An unauthenticated attacker with network access via
 HTTPS can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition
 (bsc#1204471).

CVE-2022-21618: An unauthenticated attacker with network access via
 Kerberos can compromise Oracle Java SE, Oracle GraalVM Enterprise
 Edition (bsc#1204468).

CVE-2022-21619: An unauthenticated attacker with network access via
 multiple protocols to compromise Oracle Java SE (bsc#1204473).

CVE-2022-21628: An unauthenticated attacker with network access via HTTP
 can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition
 (bsc#1204472).

CVE-2022-21624: An unauthenticated attacker with network access via
 multiple protocols to compromise Oracle Java SE, Oracle GraalVM
 Enterprise (bsc#1204475).

CVE-2022-39399: An unauthenticated attacker with network access via HTTP
 can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition
 (bsc#1204480).

Update to Java 8.0 Service Refresh 7 Fix Pack 20 [bsc#1205302]
 * Security:
 - The IBM ORB Does Not Support Object-Serialisation Data Filtering
 - Large Allocation In CipherSuite
 - Avoid Evaluating Sslalgorithmconstraints Twice
 - Cache The Results Of Constraint Checks
 - An incorrect ShortBufferException is thrown by IBMJCEPlus,
 IBMJCEPlusFIPS during cipher update operation
 - Disable SHA-1 Signed Jars For Ea
 - JSSE Performance Improvement
 - Oracle Road Map Kerberos Deprecation Of 3DES And RC4 Encryption
 * Java 8/Orb:
 - Upgrade ibmcfw.jar To Version o2228.02
 * Class Libraries:
 - Crash In Libjsor.So During An Rdma Failover
 - High CPU Consumption Observed In ZosEventPort$EventHandlerTask.run
 - Update Timezone Information To The Latest tzdata2022c
 * Jit Compiler:
 - Crash During JIT Compilation
 - Incorrect JIT Optimization Of Java Code
 - Incorrect Return From Class.isArray()
 - Unexpected ClassCastException
 - Performance Regression When Calling VM Helper Code On X86
 * X/Os Extentions:
 - Add RSA-OAEP Cipher Function To IBMJCECCA

Update to Java 8.0 Service Refresh 7 Fix Pack 16
 * Java Virtual Machine
 - Assertion failure at ClassLoaderRememberedSet.cpp
 - Assertion failure at StandardAccessBarrier.cpp when
 -Xgc:concurrentScavenge is set.
 - GC can have unflushed ownable synchronizer objects which can
 eventually lead to heap corruption and failure when
 -Xgc:concurrentScavenge is set.
 * JIT Compiler:
 - Incorrect JIT optimization of Java code
 - JAVA JIT Power: JIT compile time assert on AIX or LINUXPPC
 * Reliability and Serviceability:
 - javacore with 'kill -3' SIGQUIT signal freezes Java process");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~30.99.1", rls:"SLES12.0SP5"))) {
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
