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
  script_oid("1.3.6.1.4.1.25623.1.0.854819");
  script_version("2022-07-22T12:12:01+0000");
  script_cve_id("CVE-2020-29362");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-22 12:12:01 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-11 16:50:00 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"creation_date", value:"2022-07-16 01:02:34 +0000 (Sat, 16 Jul 2022)");
  script_name("openSUSE: Security Advisory for p11-kit (SUSE-SU-2022:2405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2405-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XUIAGKTJBYDRH7JDQTNOPWHWYCDX4ZYD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p11-kit'
  package(s) announced via the SUSE-SU-2022:2405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for p11-kit fixes the following issues:

  - CVE-2020-29362: Fixed a 4 byte overread in p11_rpc_buffer_get_byte_array
       which could lead to crashes (bsc#1180065)");

  script_tag(name:"affected", value:"'p11-kit' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit0", rpm:"libp11-kit0~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit0-debuginfo", rpm:"libp11-kit0-debuginfo~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit", rpm:"p11-kit~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-debuginfo", rpm:"p11-kit-debuginfo~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-debugsource", rpm:"p11-kit-debugsource~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-devel", rpm:"p11-kit-devel~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-nss-trust", rpm:"p11-kit-nss-trust~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-tools", rpm:"p11-kit-tools~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-tools-debuginfo", rpm:"p11-kit-tools-debuginfo~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit0-32bit", rpm:"libp11-kit0-32bit~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit0-32bit-debuginfo", rpm:"libp11-kit0-32bit-debuginfo~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-32bit", rpm:"p11-kit-32bit~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-32bit-debuginfo", rpm:"p11-kit-32bit-debuginfo~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-nss-trust-32bit", rpm:"p11-kit-nss-trust-32bit~0.23.2~150000.4.16.1", rls:"openSUSELeap15.3"))) {
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