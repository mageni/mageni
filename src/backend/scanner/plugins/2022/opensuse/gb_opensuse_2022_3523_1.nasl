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
  script_oid("1.3.6.1.4.1.25623.1.0.822631");
  script_version("2022-10-14T06:32:46+0000");
  script_cve_id("CVE-2020-35538");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-14 06:32:46 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-05 01:03:01 +0000 (Wed, 05 Oct 2022)");
  script_name("openSUSE: Security Advisory for libjpeg-turbo (SUSE-SU-2022:3523-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3523-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/224QRDBLQXCPCUZ2CJPKRSJT73IL57FI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo'
  package(s) announced via the SUSE-SU-2022:3523-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libjpeg-turbo fixes the following issues:

  - CVE-2020-35538: Fixed null pointer dereference in jcopy_sample_rows()
       function (bsc#1202915).");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo", rpm:"libjpeg62-turbo~1.5.3~150000.32.5.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo", rpm:"libjpeg-turbo~1.5.3~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debuginfo", rpm:"libjpeg-turbo-debuginfo~1.5.3~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debugsource", rpm:"libjpeg-turbo-debugsource~1.5.3~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-debuginfo", rpm:"libjpeg62-debuginfo~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-devel", rpm:"libjpeg62-devel~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo", rpm:"libjpeg62-turbo~1.5.3~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo-debugsource", rpm:"libjpeg62-turbo-debugsource~1.5.3~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-debuginfo", rpm:"libjpeg8-debuginfo~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-devel", rpm:"libjpeg8-devel~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0", rpm:"libturbojpeg0~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-debuginfo", rpm:"libturbojpeg0-debuginfo~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-32bit", rpm:"libjpeg62-32bit~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-32bit-debuginfo", rpm:"libjpeg62-32bit-debuginfo~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-devel-32bit", rpm:"libjpeg62-devel-32bit~62.2.0~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-32bit", rpm:"libjpeg8-32bit~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-32bit-debuginfo", rpm:"libjpeg8-32bit-debuginfo~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-devel-32bit", rpm:"libjpeg8-devel-32bit~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-32bit", rpm:"libturbojpeg0-32bit~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-32bit-debuginfo", rpm:"libturbojpeg0-32bit-debuginfo~8.1.2~150000.32.5.1", rls:"openSUSELeap15.3"))) {
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