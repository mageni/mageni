###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_0377_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk openSUSE-SU-2013:0377-1 (java-1_7_0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2013-03/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850419");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:35 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427",
                "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0431", "CVE-2013-0432",
                "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440",
                "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444",
                "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478",
                "CVE-2013-1480");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for java-1_7_0-openjdk openSUSE-SU-2013:0377-1 (java-1_7_0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");
  script_tag(name:"affected", value:"java-1_7_0-openjdk on openSUSE 12.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"java-1_7_0-openjdk was updated to icedtea-2.3.6
  (bnc#803379) containing various security and bugfixes:

  * Security fixes

  - S6563318, CVE-2013-0424: RMI data sanitization

  - S6664509, CVE-2013-0425: Add logging context

  - S6664528, CVE-2013-0426: Find log level matching its
  name or value given at construction time

  - S6776941: CVE-2013-0427: Improve thread pool shutdown

  - S7141694, CVE-2013-0429: Improving CORBA internals

  - S7173145: Improve in-memory representation of
  splashscreens

  - S7186945: Unpack200 improvement

  - S7186946: Refine unpacker resource usage

  - S7186948: Improve Swing data validation

  - S7186952, CVE-2013-0432: Improve clipboard access

  - S7186954: Improve connection performance

  - S7186957: Improve Pack200 data validation

  - S7192392, CVE-2013-0443: Better validation of client
  keys

  - S7192393, CVE-2013-0440: Better Checking of order of
  TLS Messages

  - S7192977, CVE-2013-0442: Issue in toolkit thread

  - S7197546, CVE-2013-0428: (proxy) Reflect about creating
  reflective proxies

  - S7200491: Tighten up JTable layout code

  - S7200493, CVE-2013-0444: Improve cache handling

  - S7200499: Better data validation for options

  - S7200500: Launcher better input validation

  - S7201064: Better dialogue checking

  - S7201066, CVE-2013-0441: Change modifiers on unused
  fields

  - S7201068, CVE-2013-0435: Better handling of UI elements

  - S7201070: Serialization to conform to protocol

  - S7201071, CVE-2013-0433: InetSocketAddress
  serialization issue

  - S8000210: Improve JarFile code quality

  - S8000537, CVE-2013-0450: Contextualize
  RequiredModelMBean class

  - S8000539, CVE-2013-0431: Introspect JMX data handling

  - S8000540, CVE-2013-1475: Improve IIOP type reuse
  management

  - S8000631, CVE-2013-1476: Restrict access to class
  constructor

  - S8001235, CVE-2013-0434: Improve JAXP HTTP handling

  - S8001242: Improve RMI HTTP conformance

  - S8001307: Modify ACC_SUPER behavior

  - S8001972, CVE-2013-1478: Improve image processing

  - S8002325, CVE-2013-1480: Improve management of images

  * Backports

  - S7057320:
  test/java/util/concurrent/Executors/AutoShutdown.java
  failing intermittently

  - S7083664: TEST_BUG: test hard code of using c:/temp but
  this dir might not exist

  - S7107613: scalability blocker in
  javax.crypto.CryptoPermissions

  - S7107616: scalability blocker in
  javax.crypto.JceSecurityManager

  - S7146424: Wildcard expansion for single entry classpath

  - S7160609: [macosx] JDK crash in libjvm.dylib ( C
  [GeForceGLDriver+0x675a] gldAttachDrawable+0x941)

  - S7160951: [macosx] ActionListener called t ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.6~3.26.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
