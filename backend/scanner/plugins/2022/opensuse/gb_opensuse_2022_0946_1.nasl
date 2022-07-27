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
  script_oid("1.3.6.1.4.1.25623.1.0.854579");
  script_version("2022-03-31T07:10:52+0000");
  script_cve_id("CVE-2021-25220");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-25 02:01:59 +0000 (Fri, 25 Mar 2022)");
  script_name("openSUSE: Security Advisory for bind (openSUSE-SU-2022:0946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0946-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H45VCAWRRO6SPMMAFDPU45PJLVOMA44Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the openSUSE-SU-2022:0946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  - CVE-2021-25220: Fixed a DNS cache poisoning vulnerability due to loose
       caching rules (bsc#1197135).");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind-devel-32bit", rpm:"bind-devel-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit", rpm:"libbind9-1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit-debuginfo", rpm:"libbind9-1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit", rpm:"libdns1605-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit-debuginfo", rpm:"libdns1605-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit", rpm:"libirs1601-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit-debuginfo", rpm:"libirs1601-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit", rpm:"libisc1606-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit-debuginfo", rpm:"libisc1606-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit", rpm:"libisccc1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit-debuginfo", rpm:"libisccc1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit", rpm:"libisccfg1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit-debuginfo", rpm:"libisccfg1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit", rpm:"libns1604-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit-debuginfo", rpm:"libns1604-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"bind-devel-32bit", rpm:"bind-devel-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit", rpm:"libbind9-1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit-debuginfo", rpm:"libbind9-1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit", rpm:"libdns1605-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit-debuginfo", rpm:"libdns1605-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit", rpm:"libirs1601-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit-debuginfo", rpm:"libirs1601-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit", rpm:"libisc1606-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit-debuginfo", rpm:"libisc1606-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit", rpm:"libisccc1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit-debuginfo", rpm:"libisccc1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit", rpm:"libisccfg1600-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit-debuginfo", rpm:"libisccfg1600-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit", rpm:"libns1604-32bit~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit-debuginfo", rpm:"libns1604-32bit-debuginfo~9.16.6~150000.12.60.1", rls:"openSUSELeap15.3"))) {
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