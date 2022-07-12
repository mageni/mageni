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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0203");
  script_cve_id("CVE-2022-0128", "CVE-2022-0213", "CVE-2022-0261", "CVE-2022-0318", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0393", "CVE-2022-0408", "CVE-2022-0413", "CVE-2022-0417", "CVE-2022-0443", "CVE-2022-0554", "CVE-2022-0572", "CVE-2022-0629", "CVE-2022-0685", "CVE-2022-0696", "CVE-2022-0714", "CVE-2022-0729", "CVE-2022-0943", "CVE-2022-1154", "CVE-2022-1160", "CVE-2022-1381", "CVE-2022-1420", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1733", "CVE-2022-1769");
  script_tag(name:"creation_date", value:"2022-05-26 04:31:19 +0000 (Thu, 26 May 2022)");
  script_version("2022-05-26T04:31:19+0000");
  script_tag(name:"last_modification", value:"2022-05-27 10:18:26 +0000 (Fri, 27 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 19:49:00 +0000 (Mon, 04 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0203");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0203.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29972");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7JBXG3MU6EZWJGJD6UTHHONHGJBYPQQT/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UCWG5L6CRQWACGVP7CYGESUB3G6QJ3GS/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UFXFAILMLUIK4MBUEZO4HNBNKYZRJ5AP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4GOY5YWTP5QUY2EFLCL7AUWA2CV57C37/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UURGABNDL77YR5FRQKTFBYNBDQX2KO7Q/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7ZLEHVP4LNAGER4ZDGUDS5V5YVQD6INF/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HBUYQBZ6GWAWJRWP7AODJ4KHW5BCKDVP/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FDNZ3N5S7UGKPUUKPGOQQGPJJK3YTW37/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/C3R36VSLO4TRX72SWB6IDJOD24BQXPX2/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/C2CQXRLBIC4S7JQVEIN5QXKQPYWB5E3J/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/X6E457NYOIRWBJHKB7ON44UY5AVTG4HU/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/A6BY5P7ERZS7KXSBCGFCOXLMLGWUUJIH/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3011");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2083924");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HIP7KG7TVS5YF3QREAY2GOGUT3YUBZAI/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ODXVYZC5Z4XRRZK7CK6B6IURYVYHA25U/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QKIX5HYKWXWG6QBCPPTPQ53GNOFHSAIS/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IUPOLEX5GXC733HL4EFYMHFU7NISJJZG/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the MGASA-2022-0203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vim is vulnerable to out of bounds read (CVE-2022-0213)
Heap-based Buffer Overflow in block_insert() in src/ops.c (CVE-2022-0261)
a heap-based OOB read of size 1 (CVE-2022-0128)
heap-based buffer overflow in utf_head_off() in mbyte.c (CVE-2022-0318)
access of memory location before start of buffer (CVE-2022-0351)
heap-based buffer overflow in init_ccline() in ex_getln.c (CVE-2022-0359)
Stack-based Buffer Overflow in spellsuggest.c (CVE-2022-0408)
use after free in src/ex_cmds.c (CVE-2022-0413)
out-of-bounds read in delete_buff_tail() in getchar.c (CVE-2022-0393)
heap-based-buffer-overflow in ex_retab() of src/indent.c (CVE-2022-0417)
heap-use-after-free in enter_buffer() of src/buffer.c (CVE-2022-0443)
heap overflow in ex_retab() may lead to crash (CVE-2022-0572)
Stack-based Buffer Overflow in vim prior to 8.2. (CVE-2022-0629)
NULL Pointer Dereference in vim prior to 8.2 (CVE-2022-0696)
buffer overflow (CVE-2022-0714)
Use of Out-of-range Pointer Offset (CVE-2022-0729)
Use of Out-of-range Pointer Offset in vim (CVE-2022-0685)
Use of Out-of-range Pointer Offset in vim (CVE-2022-0554)
Heap-based Buffer Overflow occurs in vim (CVE-2022-0943)
heap buffer overflow in get_one_sourceline (CVE-2022-1160)
use after free in utf_ptr2char (CVE-2022-1154)
global heap buffer overflow in skip_range (CVE-2022-1381)
Out-of-range Pointer Offset (CVE-2022-1420)
heap-buffer-overflow in append_command of src/ex_docmd.c (CVE-2022-1616)
heap-buffer-overflow in cmdline_erase_chars of ex_getln.c (CVE-2022-1619)
NULL Pointer Dereference in vim_regexec_string() of regexp.c (CVE-2022-1620)
heap buffer overflow (CVE-2022-1621)
buffer over-read (CVE-2022-1629)
NULL pointer dereference in vim_regexec_string() of regexp.c (CVE-2022-1674)
a buffer over-read found in scriptfile.c (CVE-2022-1769)
Heap-based Buffer Overflow in cindent.c (CVE-2022-1733)");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.4975~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~8.2.4975~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2.4975~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2.4975~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2.4975~1.mga8", rls:"MAGEIA8"))) {
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
