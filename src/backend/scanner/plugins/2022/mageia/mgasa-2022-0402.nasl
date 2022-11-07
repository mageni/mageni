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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0402");
  script_cve_id("CVE-2021-44648");
  script_tag(name:"creation_date", value:"2022-11-02 04:36:04 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-20 15:01:00 +0000 (Thu, 20 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0402");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0402.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30045");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/PEKBMOO52RXONWKB6ZKKHTVPLF6WC3KF/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LAG7HNTW3KWGP2EF5FBPHDA3R5UPDYZY/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5228");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5607-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2.0' package(s) announced via the MGASA-2022-0402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME gdk-pixbuf 2.42.6 is vulnerable to a heap-buffer overflow
vulnerability when decoding the lzw compressed stream of image data in GIF
files with lzw minimum code size equals to 12. (CVE-2021-44648)");

  script_tag(name:"affected", value:"'gdk-pixbuf2.0' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.42.2~1.2.mga8", rls:"MAGEIA8"))) {
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
