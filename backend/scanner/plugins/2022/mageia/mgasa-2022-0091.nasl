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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0091");
  script_cve_id("CVE-2022-23772", "CVE-2022-23773", "CVE-2022-23806");
  script_tag(name:"creation_date", value:"2022-03-08 04:09:07 +0000 (Tue, 08 Mar 2022)");
  script_version("2022-03-08T04:09:07+0000");
  script_tag(name:"last_modification", value:"2022-03-08 11:27:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 18:23:00 +0000 (Thu, 17 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0091)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0091");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0091.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30117");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OPXUBD6DBIW4WEXMYCUH5OXEVJIKJHR4/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2022-0091 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Overflow in Rat.SetString in math/big can lead to uncontrolled memory
consumption (CVE-2022-23772)
Incorrect access control in cmd/go (CVE-2022-23773)
Incorrect returned value in crypto/elliptic IsOnCurve (CVE-2022-23806)
The following non-security bugs were fixed:
- go#50978 crypto/elliptic: IsOnCurve returns true for invalid field
 elements
- go#50701 math/big: Rat.SetString may consume large amount of RAM and
 crash
- go#50687 cmd/go: do not treat branches with semantic-version names as
 releases
- go#50942 cmd/asm: 'compile: loop' compiler bug?
- go#50867 cmd/compile: incorrect use of CMN on arm64
- go#50812 cmd/go: remove bitbucket VCS probing
- go#50781 runtime: incorrect frame information in traceback traversal may
 hang the process.
- go#50722 debug/pe: reading debug_info section of PE files that use the
 DWARF5 form DW_FORM_line_strp causes error
- go#50683 cmd/compile: MOVWreg missing sign-extension following a Copy
 from a floating-point LoadReg
- go#50586 net/http/httptest: add fipsonly compliant certificate in for
 NewTLSServer(), for dev.boringcrypto branch
- go#50297 cmd/link: does not set section type of .init_array correctly
- go#50246 runtime: intermittent os/exec.Command.Start() Hang on Darwin in
 Presence of 'plugin' Package");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-race", rpm:"golang-race~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.17.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.17.7~1.mga8", rls:"MAGEIA8"))) {
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
