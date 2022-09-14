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
  script_oid("1.3.6.1.4.1.25623.1.0.854970");
  script_version("2022-09-13T08:08:03+0000");
  script_cve_id("CVE-2022-1720", "CVE-2022-1968", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2129", "CVE-2022-2175", "CVE-2022-2182", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2231", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2304", "CVE-2022-2343", "CVE-2022-2344", "CVE-2022-2345", "CVE-2022-2522", "CVE-2022-2571", "CVE-2022-2580", "CVE-2022-2581", "CVE-2022-2598", "CVE-2022-2816", "CVE-2022-2817", "CVE-2022-2819", "CVE-2022-2845", "CVE-2022-2849", "CVE-2022-2862", "CVE-2022-2874", "CVE-2022-2889", "CVE-2022-2923", "CVE-2022-2946", "CVE-2022-3016");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-13 08:08:03 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-10 01:01:43 +0000 (Sat, 10 Sep 2022)");
  script_name("openSUSE: Security Advisory for vim (SUSE-SU-2022:3229-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3229-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JUQDO2AKYFBQGJNMY6TUKLRL7L6M3NZB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the SUSE-SU-2022:3229-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:
  Updated to version 9.0 with patch level 0313:

  - CVE-2022-2183: Fixed out-of-bounds read through get_lisp_indent()
       (bsc#1200902).

  - CVE-2022-2182: Fixed heap-based buffer overflow through
       parse_cmd_address() (bsc#1200903).

  - CVE-2022-2175: Fixed buffer over-read through cmdline_insert_reg()
       (bsc#1200904).

  - CVE-2022-2304: Fixed stack buffer overflow in spell_dump_compl()
       (bsc#1201249).

  - CVE-2022-2343: Fixed heap-based buffer overflow in GitHub repository vim
       prior to 9.0.0044 (bsc#1201356).

  - CVE-2022-2344: Fixed another heap-based buffer overflow vim prior to
       9.0.0045 (bsc#1201359).

  - CVE-2022-2345: Fixed use after free in GitHub repository vim prior to
       9.0.0046. (bsc#1201363).

  - CVE-2022-2819: Fixed heap-based Buffer Overflow in compile_lock_unlock()
       (bsc#1202414).

  - CVE-2022-2874: Fixed NULL Pointer Dereference in generate_loadvar()
       (bsc#1202552).

  - CVE-2022-1968: Fixed use after free in utf_ptr2char (bsc#1200270).

  - CVE-2022-2124: Fixed out of bounds read in current_quote() (bsc#1200697).

  - CVE-2022-2125: Fixed out of bounds read in get_lisp_indent()
       (bsc#1200698).

  - CVE-2022-2126: Fixed out of bounds read in suggest_trie_walk()
       (bsc#1200700).

  - CVE-2022-2129: Fixed out of bounds write in vim_regsub_both()
       (bsc#1200701).

  - CVE-2022-1720: Fixed out of bounds read in grab_file_name()
       (bsc#1200732).

  - CVE-2022-2264: Fixed out of bounds read in inc() (bsc#1201132).

  - CVE-2022-2284: Fixed out of bounds read in utfc_ptr2len() (bsc#1201133).

  - CVE-2022-2285: Fixed negative size passed to memmove() due to integer
       overflow (bsc#1201134).

  - CVE-2022-2286: Fixed out of bounds read in ins_bytes() (bsc#1201135).

  - CVE-2022-2287: Fixed out of bounds read in suggest_trie_walk()
       (bsc#1201136).

  - CVE-2022-2231: Fixed null pointer dereference skipwhite() (bsc#1201150).

  - CVE-2022-2210: Fixed out of bounds read in ml_append_int() (bsc#1201151).

  - CVE-2022-2208: Fixed null pointer dereference in diff_check()
       (bsc#1201152).

  - CVE-2022-2207: Fixed out of bounds read in ins_bs() (bsc#1201153).

  - CVE-2022-2257: Fixed out of bounds read in msg_outtrans_special()
       (bsc#1201154).

  - CVE-2022-2206: Fixed out of bounds read in msg_outtrans_attr()
       (bsc#1201155).

  - CVE-2022-2522: Fixed out of bounds read via nested autocommand
       (bsc#1201863).

  - CVE-2022-2571: Fixed heap-based buff ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0313~150000.5.25.1", rls:"openSUSELeap15.3"))) {
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