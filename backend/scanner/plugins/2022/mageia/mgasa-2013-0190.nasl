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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0190");
  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2013-0190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0190");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0190.html");
  script_xref(name:"URL", value:"http://www.x.org/wiki/Development/Security/Advisory-2013-05-23");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-0897.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10569");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa, mesa' package(s) announced via the MGASA-2013-0190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds access flaw was found in Mesa. If an application using
Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox does
this), an attacker could cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application (CVE-2013-1872).

It was found that Mesa did not correctly validate messages from the X
server. A malicious X server could cause an application using Mesa to
crash or, potentially, execute arbitrary code with the privileges of the
user running the application (CVE-2013-1993).");

  script_tag(name:"affected", value:"'mesa, mesa' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglu1", rpm:"lib64mesaglu1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglu1", rpm:"lib64mesaglu1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglu1-devel", rpm:"lib64mesaglu1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglu1-devel", rpm:"lib64mesaglu1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglu1", rpm:"libmesaglu1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglu1", rpm:"libmesaglu1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglu1-devel", rpm:"libmesaglu1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglu1-devel", rpm:"libmesaglu1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~8.0.5~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~8.0.5~1.1.mga2.tainted", rls:"MAGEIA2"))) {
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
