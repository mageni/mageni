###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0272_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Java7 openSUSE-SU-2016:0272-1 (Java7)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851171");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-28 06:33:35 +0100 (Thu, 28 Jan 2016)");
  script_cve_id("CVE-2015-4871", "CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472",
                "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483",
                "CVE-2016-0494");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Java7 openSUSE-SU-2016:0272-1 (Java7)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java7'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Update OpenJDK to 7u95 / IcedTea 2.6.4 including the following fixes:

  * Security fixes

  - S8059054, CVE-2016-0402: Better URL processing

  - S8130710, CVE-2016-0448: Better attributes processing

  - S8132210: Reinforce JMX collector internals

  - S8132988: Better printing dialogues

  - S8133962, CVE-2016-0466: More general limits

  - S8137060: JMX memory management improvements

  - S8139012: Better font substitutions

  - S8139017, CVE-2016-0483: More stable image decoding

  - S8140543, CVE-2016-0494: Arrange font actions

  - S8143185: Cleanup for handling proxies

  - S8143941, CVE-2015-8126, CVE-2015-8472: Update splashscreen displays

  - S8144773, CVE-2015-7575: Further reduce use of MD5 (SLOTH)

  - S8142882, CVE-2015-4871: rebinding of the receiver of a
  DirectMethodHandle may allow a protected method to be accessed

  * Import of OpenJDK 7 u95 build 0

  - S7167988: PKIX CertPathBuilder in reverse mode doesn't work if more
  than one trust anchor is specified

  - S8068761: [TEST_BUG]
  java/nio/channels/ServerSocketChannel/AdaptServerSocket.java failed
  with SocketTimeoutException

  - S8074068: Cleanup in src/share/classes/sun/security/x509/

  - S8075773: jps running as root fails after the fix of JDK-8050807

  - S8081297: SSL Problem with Tomcat

  - S8131181: Increment minor version of HSx for 7u95 and initialize the
  build number

  - S8132082: Let OracleUcrypto accept RSAPrivateKey

  - S8134605: Partial rework of the fix for 8081297

  - S8134861: XSLT: Extension func call cause exception if namespace URI
  contains partial package name

  - S8135307: CompletionFailure thrown when calling FieldDoc.type, if
  the field's type is missing

  - S8138716: (tz) Support tzdata2015g

  - S8140244: Port fix of JDK-8075773 to MacOSX

  - S8141213: [Parfait]Potentially blocking function GetArrayLength
  called in JNI critical region at line 239 of
  jdk/src/share/native/sun/awt/image/jpeg/jpegdecoder.c in function
  GET_ARRAYS

  - S8141287: Add MD5 to jdk.certpath.disabledAlgorithms - Take 2

  - S8142928: [TEST_BUG]
  sun/security/provider/certpath/ReverseBuilder/ReverseBuild.java 8u71
  failure

  - S8143132: L10n resource file translation update

  - S8144955: Wrong changes were pushed with 8143942

  - S8145551: Test failed with Crash for Improved font lookups

  - S8147466: Add -fno-strict-overflow to
  IndicRearrangementProcessor{, 2}.cpp

  * Backports

  - S8140244: Port fix of JDK-8075773 to AIX

  - S8133196, PR2712, RH1251935: HTTPS hostname invalid issue with
  InetAddress

  - S8140620, PR2710: Find and load default.sf2 as the default soundbank
  on Linux");
  script_tag(name:"affected", value:"Java7 on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-accessibility", rpm:"java-1_7_0-openjdk-accessibility~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.95~24.27.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
