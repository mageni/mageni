# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852281");
  script_version("$Revision: 13867 $");
  script_cve_id("CVE-2018-11212", "CVE-2019-2422", "CVE-2019-2426");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 10:05:01 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-13 04:04:39 +0100 (Wed, 13 Feb 2019)");
  script_name("SuSE Update for java-11-openjdk openSUSE-SU-2019:0161-1 (java-11-openjdk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the openSUSE-SU-2019:0161_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk to version 11.0.2+7 fixes the following
  issues:

  Security issues fixed:

  - CVE-2019-2422: Better FileChannel transfer performance (bsc#1122293)

  - CVE-2019-2426: Improve web server connections

  - CVE-2018-11212: Improve JPEG processing (bsc#1122299)

  - Better route routing

  - Better interface enumeration

  - Better interface lists

  - Improve BigDecimal support

  - Improve robot support

  - Better icon support

  - Choose printer defaults

  - Proper allocation handling

  - Initial class initialization

  - More reliable p11 transactions

  - Improve NIO stability

  - Better loading of classloader classes

  - Strengthen Windows Access Bridge Support

  - Improved data set handling

  - Improved LSA authentication

  - Libsunmscapi improved interactions

  Non-security issues fix:

  - Do not resolve by default the added JavaEE modules (bsc#1120431)

  - ~2.5% regression on compression benchmark starting with 12-b11

  - java.net.http.HttpClient hangs on 204 reply without Content-length 0

  - Add additional TeliaSonera root certificate

  - Add more ld preloading related info to hs_error file on Linux

  - Add test to exercise server-side client hello processing

  - AES encrypt performance regression in jdk11b11

  - AIX: ProcessBuilder: Piping between created processes does not work.

  - AIX: Some class library files are missing the Classpath exception

  - AppCDS crashes for some uses with JRuby

  - Automate vtable/itable stub size calculation

  - BarrierSetC1::generate_referent_check() confuses register allocator

  - Better HTTP Redirection

  - Catastrophic size_t underflow in BitMap::*_large methods

  - Clip.isRunning() may return true after Clip.stop() was called

  - Compiler thread creation should be bounded by available space in memory
  and Code Cache

  - com.sun.net.httpserver.HttpServer returns Content-length header for 204
  response code

  - Default mask register for avx512 instructions

  - Delayed starting of debugging via jcmd

  - Disable all DES cipher suites

  - Disable anon and NULL cipher suites

  - Disable unsupported GCs for Zero

  - Epsilon alignment adjustments can overflow max TLAB size

  - Epsilon elastic TLAB sizing may cause misalignment

  - HotSpot update for vm_version.cpp to recognise updated VS2017

  - HttpClient does not retrieve files with large sizes over HTTP/1.1

  - IIOException 'tEXt chunk length is not proper' on opening png file

  - Improve TLS connection stability again

  - InitialDirContext ctor sometimes throws NPE if the server has sent a
  disconnection

  - Inspect stack during error reporting

  - Instead  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-11-openjdk on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-accessibility", rpm:"java-11-openjdk-accessibility~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-accessibility-debuginfo", rpm:"java-11-openjdk-accessibility-debuginfo~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.2.0~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
