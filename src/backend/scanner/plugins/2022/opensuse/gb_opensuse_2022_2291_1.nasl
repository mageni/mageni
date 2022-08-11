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
  script_oid("1.3.6.1.4.1.25623.1.0.854773");
  script_version("2022-07-13T10:13:19+0000");
  script_cve_id("CVE-2015-20107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-13 10:13:19 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 13:39:00 +0000 (Thu, 21 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-07-07 01:01:35 +0000 (Thu, 07 Jul 2022)");
  script_name("openSUSE: Security Advisory for python310 (SUSE-SU-2022:2291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2291-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/P64D5OCLWPL2MJLBNRGZCXD47S7TRRL2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310'
  package(s) announced via the SUSE-SU-2022:2291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:

  - CVE-2015-20107: avoid command injection in the mailcap module
       (bsc#1198511).

  - Update to 3.10.5:

  - Core and Builtins

  - gh-93418: Fixed an assert where an f-string has an equal sign '='
           following an expression, but there's no trailing brace. For example,
           f'{i='.

  - gh-91924: Fix __ltrace__ debug feature if the stdout encoding is not
           UTF-8. Patch by Victor Stinner.

  - gh-93061: Backward jumps after async for loops are no longer given
           dubious line numbers.

  - gh-93065: Fix contextvars HAMT implementation to handle iteration
           over deep trees.

  - The bug was discovered and fixed by Eli Libman. See
           MagicStack/immutables#84 for more details.

  - gh-92311: Fixed a bug where setting frame.f_lineno to jump
           over a list comprehension could misbehave or crash.

  - gh-92112: Fix crash triggered by an evil custom mro() on a metaclass.

  - gh-92036: Fix a crash in subinterpreters related to the garbage
           collector. When a subinterpreter is deleted, untrack all objects
           tracked by its GC. To prevent a crash in deallocator functions
           expecting objects to be tracked by the GC, leak a strong reference
           to these objects on purpose, so they are never deleted and their
           deallocator functions are not called. Patch by Victor Stinner.

  - gh-91421: Fix a potential integer overflow in _Py_DecodeUTF8Ex.

  - bpo-47212: Raise IndentationError instead of SyntaxError for a bare
           except with no following indent. Improve SyntaxError locations for
           an un-parenthesized generator used as arguments. Patch by Matthieu
           Dartiailh.

  - bpo-47182: Fix a crash when using a named unicode character like
           '\N{digit nine}' after the main interpreter has been initialized a
           second time.

  - bpo-47117: Fix a crash if we fail to decode characters in
           interactive mode if the tokenizer buffers are uninitialized. Patch
           by Pablo Galindo.

  - bpo-39829: Removed the __len__() call when initializing a list and
           moved initializing to list_extend. Patch by Jeremiah Pascual.

  - bpo-46962: Classes and functions that unconditionally declared their
           docstrings ignoring the

  - -without-doc-strings compilation flag no longer do so.

  - The classes affected are ctypes.UnionType, pickle.PickleBuffer,
           testcapi.RecursingInfinitelyEr ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python310' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-debuginfo", rpm:"libpython3_10-1_0-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-debuginfo", rpm:"python310-base-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-core-debugsource", rpm:"python310-core-debugsource~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses-debuginfo", rpm:"python310-curses-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm-debuginfo", rpm:"python310-dbm-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debuginfo", rpm:"python310-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debugsource", rpm:"python310-debugsource~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc", rpm:"python310-doc~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc-devhelp", rpm:"python310-doc-devhelp~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite", rpm:"python310-testsuite~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite-debuginfo", rpm:"python310-testsuite-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk-debuginfo", rpm:"python310-tk-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit", rpm:"libpython3_10-1_0-32bit~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit-debuginfo", rpm:"libpython3_10-1_0-32bit-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit", rpm:"python310-32bit~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit-debuginfo", rpm:"python310-32bit-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit", rpm:"python310-base-32bit~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit-debuginfo", rpm:"python310-base-32bit-debuginfo~3.10.5~150400.4.7.1", rls:"openSUSELeap15.4"))) {
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