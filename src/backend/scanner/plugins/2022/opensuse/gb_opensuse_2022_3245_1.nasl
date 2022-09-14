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
  script_oid("1.3.6.1.4.1.25623.1.0.854973");
  script_version("2022-09-13T08:08:03+0000");
  script_cve_id("CVE-2021-28902", "CVE-2021-28903", "CVE-2021-28904", "CVE-2021-28906");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-13 08:08:03 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 01:01:43 +0000 (Tue, 13 Sep 2022)");
  script_name("openSUSE: Security Advisory for libyang (SUSE-SU-2022:3245-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3245-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/54B7L6T7AUNUFL5GASSMSC3UGGNWANOC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libyang'
  package(s) announced via the SUSE-SU-2022:3245-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libyang fixes the following issues:

  - CVE-2021-28906: Fixed missing check in read_yin_leaf that can lead to
       DoS (bsc#1186378)

  - CVE-2021-28904: Fixed missing check in ext_get_plugin that lead to DoS
       (bsc#1186376).

  - CVE-2021-28903: Fixed stack overflow in lyxml_parse_mem (bsc#1186375).

  - CVE-2021-28902: Fixed missing check in read_yin_container that can lead
       to DoS (bsc#1186374).");

  script_tag(name:"affected", value:"'libyang' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp-devel", rpm:"libyang-cpp-devel~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp1", rpm:"libyang-cpp1~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp1-debuginfo", rpm:"libyang-cpp1-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-debuginfo", rpm:"libyang-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-debugsource", rpm:"libyang-debugsource~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-devel", rpm:"libyang-devel~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-extentions", rpm:"libyang-extentions~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-extentions-debuginfo", rpm:"libyang-extentions-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang1", rpm:"libyang1~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang1-debuginfo", rpm:"libyang1-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-yang", rpm:"python3-yang~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-yang-debuginfo", rpm:"python3-yang-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yang-tools", rpm:"yang-tools~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yang-tools-debuginfo", rpm:"yang-tools-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-doc", rpm:"libyang-doc~1.0.184~150300.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp-devel", rpm:"libyang-cpp-devel~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp1", rpm:"libyang-cpp1~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-cpp1-debuginfo", rpm:"libyang-cpp1-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-debuginfo", rpm:"libyang-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-debugsource", rpm:"libyang-debugsource~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-devel", rpm:"libyang-devel~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-extentions", rpm:"libyang-extentions~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-extentions-debuginfo", rpm:"libyang-extentions-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang1", rpm:"libyang1~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang1-debuginfo", rpm:"libyang1-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-yang", rpm:"python3-yang~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-yang-debuginfo", rpm:"python3-yang-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yang-tools", rpm:"yang-tools~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yang-tools-debuginfo", rpm:"yang-tools-debuginfo~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyang-doc", rpm:"libyang-doc~1.0.184~150300.3.6.1", rls:"openSUSELeap15.3"))) {
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