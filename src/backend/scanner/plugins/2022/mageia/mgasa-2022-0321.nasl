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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0321");
  script_cve_id("CVE-2021-3521");
  script_tag(name:"creation_date", value:"2022-09-12 05:06:20 +0000 (Mon, 12 Sep 2022)");
  script_version("2022-09-12T10:18:03+0000");
  script_tag(name:"last_modification", value:"2022-09-12 10:18:03 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 15:36:00 +0000 (Fri, 26 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0321");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0321.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29987");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2022:0368");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the MGASA-2022-0321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RPM does not require subkeys to have a valid binding signature
(CVE-2021-3521)");

  script_tag(name:"affected", value:"'rpm' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm-devel", rpm:"lib64rpm-devel~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm9", rpm:"lib64rpm9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmbuild9", rpm:"lib64rpmbuild9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmsign9", rpm:"lib64rpmsign9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm-devel", rpm:"librpm-devel~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm9", rpm:"librpm9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmbuild9", rpm:"librpmbuild9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmsign9", rpm:"librpmsign9~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm", rpm:"python3-rpm~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-apidocs", rpm:"rpm-apidocs~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-cron", rpm:"rpm-cron~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-audit", rpm:"rpm-plugin-audit~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-ima", rpm:"rpm-plugin-ima~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-prioreset", rpm:"rpm-plugin-prioreset~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-selinux", rpm:"rpm-plugin-selinux~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-syslog", rpm:"rpm-plugin-syslog~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-plugin-systemd-inhibit", rpm:"rpm-plugin-systemd-inhibit~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sign", rpm:"rpm-sign~4.16.1.3~1.2.mga8", rls:"MAGEIA8"))) {
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
