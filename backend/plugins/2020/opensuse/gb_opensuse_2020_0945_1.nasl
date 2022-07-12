# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853258");
  script_version("2020-07-09T12:15:58+0000");
  script_cve_id("CVE-2020-1967");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-10 11:44:30 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-08 03:04:04 +0000 (Wed, 08 Jul 2020)");
  script_name("openSUSE: Security Advisory for rust, (openSUSE-SU-2020:0945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:0945-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust, '
  package(s) announced via the openSUSE-SU-2020:0945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rust, rust-cbindgen fixes the following issues:

  rust was updated for use by Firefox 76ESR.

  - Fixed miscompilations with rustc 1.43 that lead to LTO failures
  (bsc#1173202)

  Update to version 1.43.1

  - Updated openssl-src to 1.1.1g for CVE-2020-1967.

  - Fixed the stabilization of AVX-512 features.

  - Fixed `cargo package --list` not working with unpublished dependencies.

  Update to version 1.43.0

  + Language:

  - Fixed using binary operations with `&{number}` (e.g. `&1.0`) not having
  the type inferred correctly.

  - Attributes such as `#[cfg()]` can now be used on `if` expressions.

  - Syntax only changes:

  * Allow `type Foo: Ord` syntactically.

  * Fuse associated and extern items up to defaultness.

  * Syntactically allow `self` in all `fn` contexts.

  * Merge `fn` syntax + cleanup item parsing.

  * `item` macro fragments can be interpolated into `trait`s, `impl`s, and
  `extern` blocks. For example, you may now write: ```rust macro_rules!
  mac_trait { ($i:item) => { trait T { $i } } } mac_trait! { fn foo() {}
  } ```

  * These are still rejected *semantically*, so you will likely receive an
  error but these changes can be seen and parsed by macros and
  conditional compilation.

  + Compiler

  - You can now pass multiple lint flags to rustc to override the previous
  flags.

  For example, `rustc -D unused -A unused-variables` denies everything in
  the `unused` lint group except `unused-variables` which is explicitly
  allowed. However, passing `rustc -A unused-variables -D unused` denies
  everything in the `unused` lint group **including** `unused-variables`
  since the allow flag is specified before the deny flag (and therefore
  overridden).

  - rustc will now prefer your system MinGW libraries over its bundled
  libraries if they are available on `windows-gnu`.

  - rustc now buffers errors/warnings printed in JSON.

  Libraries:

  - `Arc<[T, N]>`, `Box<[T, N]>`, and `Rc<[T, N]>`, now implement
  `TryFrom<Arc<[T]>>`, `TryFrom<Box<[T]>>`, and `TryFrom<Rc<[T]>>`
  respectively.
  **Note** These conversions are only available when `N` is `0..=32`.

  - You can now use associated constants on floats and integers directly,
  rather than having to import the module. e.g. You can now write
  `u32::MAX` or `f32::NAN` with no imports.

  - `u8::is_ascii` is now `const`.

  - `String` now implements `AsMut<str>`.

  - Added the `primitive` module to `std` and `core`. This module reexports
  Rust's primitive types. This is mainly useful in macros where you want
  avoid these types being shadowed.

  - Relaxed some of the trait bounds on `HashMap` and `HashSe ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'rust, ' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy", rpm:"clippy~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls", rpm:"rls~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analysis", rpm:"rust-analysis~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-doc", rpm:"rust-doc~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gdb", rpm:"rust-gdb~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static", rpm:"rust-std-static~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt", rpm:"rustfmt~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-doc", rpm:"cargo-doc~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-src", rpm:"rust-src~1.43.1~lp152.3.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ust-cbindgen", rpm:"ust-cbindgen~0.14.1~lp152.2.4.1", rls:"openSUSELeap15.2"))) {
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