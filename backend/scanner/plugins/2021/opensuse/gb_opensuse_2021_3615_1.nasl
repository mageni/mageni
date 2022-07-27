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
  script_oid("1.3.6.1.4.1.25623.1.0.854282");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-2161", "CVE-2021-2163", "CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2388", "CVE-2021-35550", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35567", "CVE-2021-35578", "CVE-2021-35586", "CVE-2021-35603");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 02:06:48 +0000 (Fri, 05 Nov 2021)");
  script_name("openSUSE: Security Advisory for java-1_8_0-openj9 (openSUSE-SU-2021:3615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3615-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5VOJHYCWQ5VVLZ6J4OKIW2JS6MBT7VLM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openj9'
  package(s) announced via the openSUSE-SU-2021:3615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openj9 fixes the following issues:

     Update to OpenJDK 8u312 build 07 with OpenJ9 0.29.0 virtual machine
     including Oracle July 2021 and October 2021 CPU changes

  - CVE-2021-2161: Fixed incorrect handling of partially quoted arguments in
       ProcessBuilder on Windows (bsc#1185056).

  - CVE-2021-2163: Fixed incomplete enforcement of JAR signing disabled
       algorithms (bsc#1185055).

  - CVE-2021-2341: Fixed flaw inside the FtpClient (bsc#1188564).

  - CVE-2021-2369: Fixed JAR file handling problem containing multiple
       MANIFEST.MF files (bsc#1188565).

  - CVE-2021-2388: Fixed flaw inside the Hotspot component performed range
       check elimination (bsc#1188566).

  - CVE-2021-35550: Fixed weak ciphers preferred over stronger ones for TLS
       (bsc#1191901).

  - CVE-2021-35556: Fixed excessive memory allocation in RTFParser
       (bsc#1191910).

  - CVE-2021-35559: Fixed excessive memory allocation in RTFReader
       (bsc#1191911).

  - CVE-2021-35561: Fixed excessive memory allocation in HashMap and HashSet
       (bsc#1191912).

  - CVE-2021-35564: Fixed certificates with end dates too far in the future
       can corrupt keystore (bsc#1191913).

  - CVE-2021-35565: Fixed loop in HttpsServer triggered during TLS session
       close (bsc#1191909).

  - CVE-2021-35567: Fixed incorrect principal selection when using Kerberos
       Constrained Delegation (bsc#1191903).

  - CVE-2021-35578: Fixed unexpected exception raised during TLS handshake
       (bsc#1191904).

  - CVE-2021-35586: Fixed excessive memory allocation in BMPImageReader
       (bsc#1191914).

  - CVE-2021-35603: Fixed non-constant comparison during TLS handshakes
       (bsc#1191906).");

  script_tag(name:"affected", value:"'java-1_8_0-openj9' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9", rpm:"java-1_8_0-openj9~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-accessibility", rpm:"java-1_8_0-openj9-accessibility~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debuginfo", rpm:"java-1_8_0-openj9-debuginfo~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debugsource", rpm:"java-1_8_0-openj9-debugsource~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo", rpm:"java-1_8_0-openj9-demo~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo-debuginfo", rpm:"java-1_8_0-openj9-demo-debuginfo~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel", rpm:"java-1_8_0-openj9-devel~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless", rpm:"java-1_8_0-openj9-headless~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-src", rpm:"java-1_8_0-openj9-src~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-javadoc", rpm:"java-1_8_0-openj9-javadoc~1.8.0.312~3.18.2", rls:"openSUSELeap15.3"))) {
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