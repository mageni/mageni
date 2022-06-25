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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0481");
  script_cve_id("CVE-2021-3778", "CVE-2021-3796");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 19:23:00 +0000 (Fri, 24 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0481");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0481.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29501");
  script_xref(name:"URL", value:"https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273/");
  script_xref(name:"URL", value:"https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5093-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/10/01/1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the MGASA-2021-0481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-3778: vim: Heap-based Buffer Overflow in utf_ptr2char()
Fix: patch 8.2.3409: reading beyond end of line with invalid utf-8 character
When vim 8.2 is built with --with-features=huge --enable-gui=none
and address sanitizer, a heap-buffer overflow occurs when running:
echo 'Ywp2XTCqCi4KeQpAMA==' <pipe> base64 -d > fuzz000.txt
vim -u NONE -X -Z -e -s -S fuzz000.txt -c :qa!

CVE-2021-3796: vim: Use After Free in nv_replace()
Fix: patch 8.2.3428: using freed memory when replacing
When vim 8.2 is built with --with-features=huge --enable-gui=none
and address sanitizer, a use-after-free occurs when running:
LC_ALL=C vim -U NONE -X -Z -e -s -S poc -c :qa!
with the poc file provided.");

  script_tag(name:"affected", value:"'vim' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.2143~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~8.2.2143~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2.2143~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2.2143~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2.2143~3.2.mga8", rls:"MAGEIA8"))) {
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
