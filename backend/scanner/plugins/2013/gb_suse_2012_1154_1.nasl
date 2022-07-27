###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1154_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk openSUSE-SU-2012:1154-1 (java-1_7_0-openjdk)
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
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-09/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850432");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:23 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-0547", "CVE-2012-1682", "CVE-2012-3136", "CVE-2012-4681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for java-1_7_0-openjdk openSUSE-SU-2012:1154-1 (java-1_7_0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");
  script_tag(name:"affected", value:"java-1_7_0-openjdk on openSUSE 12.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Java-1_7_0-openjdk was updated to fix a remote exploit
  (CVE-2012-4681).

  Also bugfixes were done:

  - fix build on ARM and i586

  - remove files that are no longer used


  - zero build can be enabled using rpmbuild (osc build)

  - -with zero

  - add hotspot 2.1 needed for zero

  - fix filelist on %{ix86}

  * Security fixes

  - S7162476, CVE-2012-1682: XMLDecoder security issue via
  ClassFinder

  - S7194567, CVE-2012-3136: Improve long term persistence
  of java.beans objects

  - S7163201, CVE-2012-0547: Simplify toolkit internals
  references

  - RH852051, CVE-2012-4681, S7162473: Reintroduce
  PackageAccessible checks removed in  6788531.

  * OpenJDK

  - Fix Zero FTBFS issues with 2.3

  - S7180036: Build failure in Mac platform caused by fix #
  7163201

  - S7182135: Impossible to use some editors directly

  - S7183701: [TEST]
  closed/java/beans/security/TestClassFinder.java
  compilation failed

  - S7185678:
  java/awt/Menu/NullMenuLabelTest/NullMenuLabelTest.java
  failed with NPE

  * Bug fixes

  - PR1149: Zero-specific patch files not being packaged

  - use icedtea tarball for build again, this led into
  following dropped files because the are already in the
  tarball and simplified %prep and %build

  - drop class-rewriter.tar.gz

  - drop systemtap-tapset.tar.gz

  - drop desktop-files.tar.gz

  - drop nss.cfg

  - drop pulseaudio.tar.gz

  - drop remove-intree-libraries.sh

  - add archives from icedtea7-forest-2.3 for openjdk,
  corba, jaxp, jaxws, jdk, langtools and hotspot

  - drop rhino.patch, pulse-soundproperties and systemtap
  patch

  - move gnome bridge patches before make as it's irritating
  to have the patch fail after openjdk is built

  - use explicit file attributes in %files sections to
  prevent the file permissions problems in a future (like
  bnc#770040)

  - changed version scheme, so it now matches Oracle Java
  1.7.0.6 == Java7 u 6

  - update to icedtea-2.3.1 / OpenJDK7 u6 (bnc#777499)

  * Security fixes

  - RH852051, CVE-2012-4681: Reintroduce PackageAccessible
  checks removed in  6788531.

  * Bug fixes

  - PR902: PulseAudioClip getMicrosecondsLength() returns
  length in milliseconds, not microseconds

  - PR986: IcedTea7 fails to build with IcedTea6 CACAO due
  to low max heapsize

  - PR1050: Stream objects not garbage collected

  - PR1119: Only add classes to rt-source-files.txt if the
  class (or one or more of its methods/fields) are
  actually missing from the boot JDK

  - PR1137: Allow JARs to be optionally compressed by
  setting COMPRESS_JARS

  * OpenJDK

  - Make dynamic support for GConf work again.

  - PR1095: Add configure option for -Werror

  - PR1101: Undefined symbols on GNU/Linux SPARC

  - PR1140: Unnecessary diz files should not be installed

  - S7192804, PR1138: Build should not install jvisualvm
  man page for OpenJDK

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

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.6~3.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
