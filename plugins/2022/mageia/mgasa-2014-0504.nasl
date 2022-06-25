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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0504");
  script_cve_id("CVE-2014-7271", "CVE-2014-7272");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 23:50:00 +0000 (Tue, 27 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0504");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0504.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14238");
  script_xref(name:"URL", value:"https://github.com/sddm/sddm/releases/tag/v0.10.0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-October/141494.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxcb, sddm' package(s) announced via the MGASA-2014-0504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sddm may in some cases allow unauthenticated logins as the sddm user
(CVE-2014-7271).

Sddm is vulnerable to a race condition in XAUTHORITY file generation
(CVE-2014-7272).

Sddm has been updated to version 0.10.0, fixing these issues and several
other bugs, and adding new functionality.

libxcb packages have been updated to work with sddm.");

  script_tag(name:"affected", value:"'libxcb, sddm' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-composite0", rpm:"lib64xcb-composite0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-damage0", rpm:"lib64xcb-damage0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-devel", rpm:"lib64xcb-devel~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-dpms0", rpm:"lib64xcb-dpms0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-dri2_0", rpm:"lib64xcb-dri2_0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-glx0", rpm:"lib64xcb-glx0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-randr0", rpm:"lib64xcb-randr0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-record0", rpm:"lib64xcb-record0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-render0", rpm:"lib64xcb-render0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-res0", rpm:"lib64xcb-res0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-screensaver0", rpm:"lib64xcb-screensaver0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-shape0", rpm:"lib64xcb-shape0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-shm0", rpm:"lib64xcb-shm0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-static-devel", rpm:"lib64xcb-static-devel~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-sync0", rpm:"lib64xcb-sync0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xevie0", rpm:"lib64xcb-xevie0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xf86dri0", rpm:"lib64xcb-xf86dri0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xfixes0", rpm:"lib64xcb-xfixes0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xinerama0", rpm:"lib64xcb-xinerama0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xkb0", rpm:"lib64xcb-xkb0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xprint0", rpm:"lib64xcb-xprint0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xtest0", rpm:"lib64xcb-xtest0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xv0", rpm:"lib64xcb-xv0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb-xvmc0", rpm:"lib64xcb-xvmc0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xcb1", rpm:"lib64xcb1~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb", rpm:"libxcb~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-doc", rpm:"libxcb-doc~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2_0", rpm:"libxcb-dri2_0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-static-devel", rpm:"libxcb-static-devel~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync0", rpm:"libxcb-sync0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xevie0", rpm:"libxcb-xevie0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb0", rpm:"libxcb-xkb0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xprint0", rpm:"libxcb-xprint0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.9.1~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sddm", rpm:"sddm~0.10.0~1.mga4", rls:"MAGEIA4"))) {
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
