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
  script_oid("1.3.6.1.4.1.25623.1.0.854559");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2022-21658");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 17:55:00 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 08:28:30 +0000 (Wed, 23 Mar 2022)");
  script_name("openSUSE: Security Advisory for rust, (openSUSE-SU-2022:0843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0843-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZODX3XK3LNWUDIGOVAOXXYOTCRZZ4CMJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust,'
  package(s) announced via the openSUSE-SU-2022:0843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rust, rust1.58, rust1.59 fixes the following issues:
  This update provides both rust1.58 and rust1.59.
  Changes in rust1.58:
  - Add recommends for GCC for installs to be able to link.
     - Add suggests for lld/clang which are faster than gcc for linking to
       allow users choice on what they use.
     - CVE-2022-21658: Resolve race condition in std::fs::remove_dir_all
       (bsc#1194767)
  Version 1.58.0 (2022-01-13) ==========================
  Language
     --------
     - [Format strings can now capture arguments simply by writing `{ident}` in
       the string.][90473] This works in all macros accepting format strings.
       Support for this in `panic!` (`panic!('{ident}')`) requires the 2021
       edition  panic invocations in previous editions that appear to be trying
       to use this will result in a warning lint about not having the intended
       effect.
     - [`*const T` pointers can now be dereferenced in const contexts.][89551]
     - [The rules for when a generic struct implements `Unsize` have been
       relaxed.][90417] Compiler
     --------
     - [Add LLVM CFI support to the Rust compiler][89652]
     - [Stabilize -Z strip as -C strip][90058]. Note that while release builds
       already don't add debug symbols for the code you compile, the compiled
       standard library that ships with Rust includes debug symbols, so you may
       want to use the `strip` option to remove these symbols to produce
       smaller release binaries. Note that this release only includes support
       in rustc, not directly in cargo.
     - [Add support for LLVM coverage mapping format versions 5 and 6][91207]
     - [Emit LLVM optimization remarks when enabled with `-Cremark`][90833]
     - [Update the minimum external LLVM to 12][90175]
     - [Add `x86_64-unknown-none` at Tier 3*][89062]
     - [Build musl dist artifacts with debuginfo enabled][90733]. When building
       release binaries using musl, you may want to use the newly stabilized
       strip option to remove these debug symbols, reducing the size of your
       binaries.
     - [Don't abort compilation after giving a lint error][87337]
     - [Error messages point at the source of trait bound obligations in more
       places][89580] * Refer to Rust's [platform support
       page][platform-support-doc] for more information on Rust's tiered
       platform support.
  Libraries
     ---------
  - [All remaining functions in the standard library have `#[must_use]`
       annotations where appropriate][89692], producing a warning when ignoring
       their return value ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'rust,' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.59.0~150300.21.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.59.0~150300.21.20.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.59.0~150300.21.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo1.58", rpm:"cargo1.58~1.58.0~150300.7.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo1.58-debuginfo", rpm:"cargo1.58-debuginfo~1.58.0~150300.7.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo1.59", rpm:"cargo1.59~1.59.0~150300.7.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo1.59-debuginfo", rpm:"cargo1.59-debuginfo~1.59.0~150300.7.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.59.0~150300.21.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust1.58", rpm:"rust1.58~1.58.0~150300.7.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust1.58-debuginfo", rpm:"rust1.58-debuginfo~1.58.0~150300.7.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust1.59", rpm:"rust1.59~1.59.0~150300.7.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust1.59-debuginfo", rpm:"rust1.59-debuginfo~1.59.0~150300.7.4.2", rls:"openSUSELeap15.3"))) {
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