# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853779");
  script_version("2021-04-30T07:59:33+0000");
  script_cve_id("CVE-2021-21372", "CVE-2021-21373", "CVE-2021-21374");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-30 10:37:53 +0000 (Fri, 30 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-27 03:02:07 +0000 (Tue, 27 Apr 2021)");
  script_name("openSUSE: Security Advisory for nim (openSUSE-SU-2021:0618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0618-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NV5NCUH7W5BZXNXEYHHUQGISDZUK64IU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nim'
  package(s) announced via the openSUSE-SU-2021:0618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nim fixes the following issues:

     num was updated to version 1.2.12:

  * Fixed GC crash resulting from inlining of the memory allocation procs

  * Fixed incorrect raises effect for $(NimNode) (#17454)

     From version 1.2.10:

  * Fixed JS backend doesn't handle float- int type conversion
       (#8404)

  * Fixed The try except not work when the OSError: Too many
       open files error occurs! (#15925)

  * Fixed Nim emits #line 0 C preprocessor directives with
       debugger:native, with ICE in gcc-10 (#15942)

  * Fixed tfuturevar fails when activated (#9695)

  * Fixed nre.escapeRe is not gcsafe (#16103)

  * Fixed Error: internal error: genRecordFieldAux - in the
       version-1-4 branch (#16069)

  * Fixed -d:fulldebug switch does not compile with gc:arc (#16214)

  * Fixed osLastError may randomly raise defect and crash (#16359)

  * Fixed generic importc procs dont work (breaking lots
       of vmops procs for js) (#16428)

  * Fixed Concept: codegen ignores parameter passing (#16897)

  * Fixed {.push exportc.} interacts with anonymous functions (#16967)

  * Fixed memory allocation during {.global.} init breaks GC (#17085)

  * Fixed 'Nimble arbitrary code execution for specially crafted package

  * Fixed Defer and gc:arc (#15071)

  * Fixed ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nim' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"nim", rpm:"nim~1.2.12~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nim-debuginfo", rpm:"nim-debuginfo~1.2.12~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
