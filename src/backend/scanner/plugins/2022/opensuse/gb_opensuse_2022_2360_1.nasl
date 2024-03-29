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
  script_oid("1.3.6.1.4.1.25623.1.0.854810");
  script_version("2022-07-22T12:12:01+0000");
  script_cve_id("CVE-2022-1586");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-07-22 12:12:01 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 03:15:00 +0000 (Thu, 26 May 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 01:01:39 +0000 (Wed, 13 Jul 2022)");
  script_name("openSUSE: Security Advisory for pcre2 (SUSE-SU-2022:2360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2360-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B73K4AVJDMZXEYUEHOYLDUGBLQNOANKW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre2'
  package(s) announced via the SUSE-SU-2022:2360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcre2 fixes the following issues:

  - CVE-2022-1586: Fixed unicode property matching issue. (bsc#1199232)");

  script_tag(name:"affected", value:"'pcre2' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-debuginfo", rpm:"libpcre2-16-0-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-debuginfo", rpm:"libpcre2-32-0-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-debuginfo", rpm:"libpcre2-posix2-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel", rpm:"pcre2-devel~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel-static", rpm:"pcre2-devel-static~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools", rpm:"pcre2-tools~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools-debuginfo", rpm:"pcre2-tools-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-doc", rpm:"pcre2-doc~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit", rpm:"libpcre2-16-0-32bit~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit-debuginfo", rpm:"libpcre2-16-0-32bit-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit", rpm:"libpcre2-32-0-32bit~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit-debuginfo", rpm:"libpcre2-32-0-32bit-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit", rpm:"libpcre2-8-0-32bit~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit-debuginfo", rpm:"libpcre2-8-0-32bit-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit", rpm:"libpcre2-posix2-32bit~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit-debuginfo", rpm:"libpcre2-posix2-32bit-debuginfo~10.39~150400.4.3.1", rls:"openSUSELeap15.4"))) {
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