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
  script_oid("1.3.6.1.4.1.25623.1.0.853619");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-14803");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:57:04 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for java-1_8_0-openjdk (openSUSE-SU-2021:0374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0374-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IE6Q2IB2YXUXIWFBPF2P2FIHVNJLBUPC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the openSUSE-SU-2021:0374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

  - Update to version jdk8u282 (icedtea 3.18.0)

  * January 2021 CPU (bsc#1181239)

  * Security fixes
         + JDK-8247619: Improve Direct Buffering of Characters (CVE-2020-14803)

  * Import of OpenJDK 8 u282 build 01
         + JDK-6962725: Regtest javax/swing/JFileChooser/6738668/
           /bug6738668.java fails under Linux
         + JDK-8025936: Windows .pdb and .map files does not have proper
           dependencies setup
         + JDK-8030350: Enable additional compiler warnings for GCC
         + JDK-8031423: Test java/awt/dnd/DisposeFrameOnDragCrash/
           /DisposeFrameOnDragTest.java fails by Timeout on Windows
         + JDK-8036122: Fix warning &#x27 format not a string literal&#x27
         + JDK-8051853: new
  URI('x/').resolve('..').getSchemeSpecificPart()
           returns null!
         + JDK-8132664: closed/javax/swing/DataTransfer/DefaultNoDrop/
           /DefaultNoDrop.java locks on Windows
         + JDK-8134632: Mark javax/sound/midi/Devices/ /InitializationHang.java
           as headful
         + JDK-8148854: Class names 'SomeClass' and 'LSomeClass '
  treated by
           JVM as an equivalent
         + JDK-8148916: Mark bug6400879.java as intermittently failing
         + JDK-8148983: Fix extra comma in changes for JDK-8148916
         + JDK-8160438: javax/swing/plaf/nimbus/8057791/bug8057791.java fails
         + JDK-8165808: Add release barriers when allocating objects with
           concurrent collection
         + JDK-8185003: JMX: Add a version of ThreadMXBean.dumpAllThreads with
           a maxDepth argument
         + JDK-8202076: test/jdk/java/io/File/WinSpecialFiles.java on windows
           with VS2017
         + JDK-8207766: [testbug] Adapt tests for Aix.
         + JDK-8212070: Introduce diagnostic flag to abort VM on failed JIT
           compilation
         + JDK-8213448: [TESTBUG] enhance jfr/jvm/TestDumpOnCrash
         + JDK-8215727: Restore JFR thread sampler loop to old / previous
           behavior
         + JDK-8220657: JFR.dump does not work when filename is set
         + JDK-8221342: [TESTBUG] Generate Dockerfile for docker testing
         + JDK-8224502: [TESTBUG] JDK docker test TestSystemMetrics.java fails
           with access issues and OOM
         + JDK-8231209: [REDO] ThreadMXBean::getThreadAllocatedBytes() can be
           quicker for self thread
         + JDK-8231968: getCurrentThreadAllocatedBytes default implementation
           s/b getThreadAllocatedBytes
         + JDK-8232114: JVM crashed at imjpapi.dll i ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.282~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
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