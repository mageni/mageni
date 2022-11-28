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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0438");
  script_cve_id("CVE-2022-3554", "CVE-2022-3555");
  script_tag(name:"creation_date", value:"2022-11-25 04:11:46 +0000 (Fri, 25 Nov 2022)");
  script_version("2022-11-25T10:12:49+0000");
  script_tag(name:"last_modification", value:"2022-11-25 10:12:49 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0438)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0438");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0438.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31137");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012923.html");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2022-November/003253.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TPCKHK5VITSWJVYMQDZ642ZYBWJACES3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11' package(s) announced via the MGASA-2022-0438 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak in XRegisterIMInstantiateCallback(). (CVE-2022-3554)
Memory leak in _XFreeX11XCBStructure(). (CVE-2022-3555)");

  script_tag(name:"affected", value:"'libx11' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-devel", rpm:"lib64x11-devel~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-xcb1", rpm:"lib64x11-xcb1~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-devel", rpm:"libx11-devel~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-xcb1", rpm:"libx11-xcb1~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.7.0~1.3.mga8", rls:"MAGEIA8"))) {
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
