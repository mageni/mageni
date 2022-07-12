###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1507_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_8_0-openjdk openSUSE-SU-2017:1507-1 (java-1_8_0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851565");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-06-09 06:51:15 +0200 (Fri, 09 Jun 2017)");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514",
                "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_8_0-openjdk openSUSE-SU-2017:1507-1 (java-1_8_0-openjdk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes
  the following issues: - Upgrade to version jdk8u131 (icedtea 3.4.0) -
  bsc#1034849 * Security fixes - S8163520, CVE-2017-3509: Reuse cache entries -
  S8163528, CVE-2017-3511: Better library loading - S8165626, CVE-2017-3512:
  Improved window framing - S8167110, CVE-2017-3514: Windows peering issue -
  S8168699: Validate special case invocations - S8169011, CVE-2017-3526: Resizing
  XML parse trees - S8170222, CVE-2017-3533: Better transfers of files - S8171121,
  CVE-2017-3539: Enhancing jar checking - S8171533, CVE-2017-3544: Better email
  transfer - S8172299: Improve class processing * New features - PR1969: Add
  AArch32 JIT port - PR3297: Allow Shenandoah to be used on AArch64 - PR3340:
  jstack.stp should support AArch64 * Import of OpenJDK 8 u131 build 11 -
  S6474807: (smartcardio) CardTerminal.connect() throws CardException instead of
  CardNotPresentException - S6515172, PR3346: Runtime.availableProcessors()
  ignores Linux taskset command - S7155957:
  closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.java hangs on win 64 bit
  with jdk8 - S7167293: FtpURLConnection connection leak on FileNotFoundException

  - S8035568: [macosx] Cursor management unification - S8079595: Resizing dialog
  which is JWindow parent makes JVM crash - S8130769: The new menu can't be shown
  on the menubar after clicking the 'Add' button. - S8146602:
  jdk/test/sun/misc/URLClassPath/ClassnameCharTest.java test fails with
  NullPointerException - S8147842: IME Composition Window is displayed at
  incorrect location - S8147910, PR3346: Cache initial active_processor_count -
  S8150490: Update OS detection code to recognize Windows Server 2016 - S8160951:
  [TEST_BUG] javax/xml/bind/marshal/8134111/UnmarshalTest.java should be added
  into :needs_jre group - S8160958: [TEST_BUG]
  java/net/SetFactoryPermission/SetFactoryPermission.java should be added into
  :needs_compact2 group - S8161147: jvm crashes when -XX:+UseCountedLoopSafepoints
  is enabled - S8161195: Regression:
  closed/javax/swing/text/FlowView/LayoutTest.java - S8161993, PR3346: G1 crashes
  if active_processor_count changes during startup - S8162876: [TEST_BUG]
  sun/net/www/protocol/http/HttpInputStream.java fails intermittently - S8162916:
  Test sun/security/krb5/auto/UnboundSSL.java fails - S8164533:
  sun/security/ssl/SSLSocketImpl/CloseSocket.java failed with 'Error while
  cleaning up threads after test' - S8167179: Make XSL generated namespace
  prefixes local to transformation process - S8168774: Polymorhic signature method
  chec ... Description truncated, for more information please check the Reference
  URL");
  script_tag(name:"affected", value:"java-1_8_0-openjdk on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.131~10.8.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}