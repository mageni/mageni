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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0430");
  script_cve_id("CVE-2022-2000", "CVE-2022-2042", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2129", "CVE-2022-2175", "CVE-2022-2182", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2231", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2288", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2343", "CVE-2022-2344", "CVE-2022-2345", "CVE-2022-2522", "CVE-2022-2571", "CVE-2022-2580", "CVE-2022-2581", "CVE-2022-2598", "CVE-2022-2816", "CVE-2022-2817", "CVE-2022-2819", "CVE-2022-2845", "CVE-2022-2849", "CVE-2022-2862", "CVE-2022-2874", "CVE-2022-2889", "CVE-2022-2923", "CVE-2022-2946", "CVE-2022-2980", "CVE-2022-2982", "CVE-2022-3016", "CVE-2022-3037", "CVE-2022-3099", "CVE-2022-3134", "CVE-2022-3234", "CVE-2022-3235", "CVE-2022-3256", "CVE-2022-3278", "CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352", "CVE-2022-3705");
  script_tag(name:"creation_date", value:"2022-11-21 04:17:51 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:17:51+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:17:51 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 23:35:00 +0000 (Fri, 30 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0430");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0430.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30561");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4JJNUS4AEVYSEJMCK6JZB57QHD5V2G4O/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3053");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5492-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GFD2A4YLBR7OIRHTL7CK6YNMEIQ264CN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UXPO5EHDV6J4B27E65DOQGZFELUFPRSK/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/43Y3VJPOTTY3NTREDIFUPITM2POG4ZLP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CHFAR6OY6G77M6GXCJT75A4KITLNR6GO/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/C72HDIMR3KTTAO7QGTXWUMPBNFUFIBRD/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RY3GEN2Q46ZJKSNHTN2XB6B3VAJBEILN/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012199.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JUQDO2AKYFBQGJNMY6TUKLRL7L6M3NZB/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/XWOJOA7PZZAMBI5GFTL6PWHXMWSDLUXL/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LSSEWQLK55MCNT4Z2IIJEJYEI5HLCODI/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4JCW33NOLMELTTTDJH7WGDIFJZ5YEEMK/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3182");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the MGASA-2022-0430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.
(CVE-2022-2000, CVE-2022-2129, CVE-2022-2210)

Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-2042)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.
(CVE-2022-2124, CVE-2022-2175)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.
(CVE-2022-2125, CVE-2022-2182, CVE-2022-2207)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.
(CVE-2022-2126, CVE-2022-2183, CVE-2022-2206)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.
(CVE-2022-2208)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.
(CVE-2022-2231)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.
(CVE-2022-2257, CVE-2022-2286, CVE-2022-2287, CVE-2022-2288)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.
(CVE-2022-2264, CVE-2022-2284)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.
(CVE-2022-2285)

Use After Free in GitHub repository vim/vim prior to 9.0. (CVE-2022-2289)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.
(CVE-2022-2304)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044.
(CVE-2022-2343)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045.
(CVE-2022-2344)

Use After Free in GitHub repository vim/vim prior to 9.0.0046.
(CVE-2022-2345)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0061.
(CVE-2022-2522)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101.
(CVE-2022-2571)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0102.
(CVE-2022-2580)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0104.
(CVE-2022-2581)

Undefined Behavior for Input to API in GitHub repository vim/vim prior to
9.0.0100. (CVE-2022-2598)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0212.
(CVE-2022-2816)

Use After Free in GitHub repository vim/vim prior to 9.0.0213.
(CVE-2022-2817)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0211.
(CVE-2022-2819)

Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218.
(CVE-2022-2845)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0220.
(CVE-2022-2849)

Use After Free in GitHub repository vim/vim prior to 9.0.0221.
(CVE-2022-2862)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0224.
(CVE-2022-2874)

Use After Free in GitHub repository vim/vim prior to 9.0.0225.
(CVE-2022-2889)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240.
(CVE-2022-2923)

Use After Free in GitHub repository vim/vim prior to 9.0.0246.
(CVE-2022-2946)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259.
(CVE-2022-2980)

Use After Free in GitHub repository vim/vim prior to 9.0.0260.
(CVE-2022-2982)

Use After Free in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.828~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~9.0.828~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0.828~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0.828~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0.828~1.mga8", rls:"MAGEIA8"))) {
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
