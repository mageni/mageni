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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0002");
  script_cve_id("CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113", "CVE-2017-13728", "CVE-2017-13729", "CVE-2017-13730", "CVE-2017-13731", "CVE-2017-13732", "CVE-2017-13733", "CVE-2017-16879");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0002");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0002.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21197");
  script_xref(name:"URL", value:"http://invisible-island.net/ncurses/NEWS.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-07/msg00071.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-08/msg00048.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2017-12/msg00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the MGASA-2018-0002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible RCE via stack-based buffer overflow in the fmt_entry function
(CVE-2017-10684).

Possible RCE with format string vulnerability in the fmt_entry function
(CVE-2017-10685).

Illegal address access in append_acs (CVE-2017-11112).

Dereferencing NULL pointer in _nc_parse_entry (CVE-2017-11113).

Fix infinite loop in the next_char function in comp_scan.c
(CVE-2017-13728).

Fix illegal address access in the _nc_save_str (CVE-2017-13729).

Fix illegal address access in the function _nc_read_entry_source()
(CVE-2017-13730).

Fix illegal address access in the function postprocess_termcap()
(CVE-2017-13731).

Fix illegal address access in the function dump_uses() (CVE-2017-13732).

Fix illegal address access in the fmt_entry function (CVE-2017-13733).

Fix stack-based buffer overflow in the _nc_write_entry() function
(CVE-2017-16879).");

  script_tag(name:"affected", value:"'ncurses' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses-devel", rpm:"lib64ncurses-devel~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses5", rpm:"lib64ncurses5~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses6", rpm:"lib64ncurses6~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw-devel", rpm:"lib64ncursesw-devel~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw5", rpm:"lib64ncursesw5~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw6", rpm:"lib64ncursesw6~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses-devel", rpm:"libncurses-devel~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5", rpm:"libncurses5~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6", rpm:"libncurses6~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw-devel", rpm:"libncursesw-devel~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw5", rpm:"libncursesw5~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw6", rpm:"libncursesw6~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses", rpm:"ncurses~6.0~8.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-extraterms", rpm:"ncurses-extraterms~6.0~8.1.mga6", rls:"MAGEIA6"))) {
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
