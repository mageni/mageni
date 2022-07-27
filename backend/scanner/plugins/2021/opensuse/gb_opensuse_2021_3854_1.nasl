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
  script_oid("1.3.6.1.4.1.25623.1.0.854330");
  script_version("2021-12-03T04:02:27+0000");
  script_cve_id("CVE-2017-18267", "CVE-2018-13988", "CVE-2018-16646", "CVE-2018-18897", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-19149", "CVE-2018-20481", "CVE-2018-20551", "CVE-2018-20650", "CVE-2018-20662", "CVE-2019-10871", "CVE-2019-10872", "CVE-2019-14494", "CVE-2019-7310", "CVE-2019-9200", "CVE-2019-9631", "CVE-2019-9903", "CVE-2019-9959", "CVE-2020-27778");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-02 02:02:17 +0000 (Thu, 02 Dec 2021)");
  script_name("openSUSE: Security Advisory for poppler (openSUSE-SU-2021:3854-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3854-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TS7QPSEQIBQO7BALZOE3TN7IO7IMHK3Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the openSUSE-SU-2021:3854-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  - CVE-2017-18267: Fixed an infinite recursion that would allow remote
       attackers to cause a denial of service (bsc#1092945).

  - CVE-2018-13988: Added an improper implementation check which otherwise
       could allow buffer overflows, memory corruption, and denial of service
       (bsc#1102531).

  - CVE-2018-16646: Fixed an infinite recursion which could allow a
       denial-of-service attack via a specially crafted PDF file (bsc#1107597).

  - CVE-2018-18897: Fixed a memory leak (bsc#1114966).

  - CVE-2018-19058: Fixed a bug which could allow a denial-of-service attack
       via a specially crafted PDF file (bsc#1115187).

  - CVE-2018-19059: Fixed an out-of-bounds read access which could allow a
       denial-of-service attack (bsc#1115186).

  - CVE-2018-19060: Fixed a NULL pointer dereference which could allow a
       denial-of-service attack (bsc#1115185).

  - CVE-2018-19149: Fixed a NULL pointer dereference which could allow a
       denial-of-service attack (bsc#1115626).

  - CVE-2018-20481: Fixed a NULL pointer dereference while handling
       unallocated XRef entries which could allow a denial-of-service attack
       (bsc#1120495).

  - CVE-2018-20551: Fixed a reachable assertion which could allow a
       denial-of-service attack through specially crafted PDF files
       (bsc#1120496).

  - CVE-2018-20650: Fixed a reachable assertion which could allow
       denial-of-service through specially crafted PDF files (bsc#1120939).

  - CVE-2018-20662: Fixed a bug which could potentially crash the running
       process by SIGABRT resulting in a denial-of-service attack through a
       specially crafted PDF file (bsc#1120956).

  - CVE-2019-10871: Fixed a heap-based buffer  over-read in the function
       PSOutputDev::checkPageSlice at PSOutputDev.cc (bsc#1131696).

  - CVE-2019-10872: Fixed a heap-based buffer over-read in the function
       Splash::blitTransparent at splash/Splash.cc (bsc#1131722).

  - CVE-2019-14494: Fixed a divide-by-zero error in the function
       SplashOutputDev::tilingPatternFill (bsc#1143950).

  - CVE-2019-7310: Fixed a heap-based buffer over-read (due to an integer
       signedness error in the XRef::getEntry function in XRef.cc) that allows
       remote attackers to cause a denial of service or possibly have
       unspecified other impact via a crafted PDF document (bsc#1124150).

  - CVE-2019-9200: Fixed a heap-based buffer underwrite which could allow
       denial-of-service attack through a specially crafted PDF file
       (bsc#11 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'poppler' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73", rpm:"libpoppler73~0.62.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-debuginfo", rpm:"libpoppler73-debuginfo~0.62.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit", rpm:"libpoppler73-32bit~0.62.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit-debuginfo", rpm:"libpoppler73-32bit-debuginfo~0.62.0~4.6.1", rls:"openSUSELeap15.3"))) {
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