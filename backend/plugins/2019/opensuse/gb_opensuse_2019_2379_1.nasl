# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852749");
  script_version("2019-10-30T10:03:24+0000");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-30 10:03:24 +0000 (Wed, 30 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-27 03:00:53 +0000 (Sun, 27 Oct 2019)");
  script_name("openSUSE Update for procps openSUSE-SU-2019:2379-1 (procps)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00059.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps'
  package(s) announced via the openSUSE-SU-2019:2379_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for procps fixes the following issues:

  procps was updated to 3.3.15. (bsc#1092100)

  Following security issues were fixed:

  - CVE-2018-1122: Prevent local privilege escalation in top. If a user ran
  top with HOME unset in an attacker-controlled directory, the attacker
  could have achieved privilege escalation by exploiting one of several
  vulnerabilities in the config_file() function (bsc#1092100).

  - CVE-2018-1123: Prevent denial of service in ps via mmap buffer overflow.
  Inbuilt protection in ps mapped a guard page at the end of the overflowed
  buffer, ensuring that the impact of this flaw is limited to a crash
  (temporary denial of service) (bsc#1092100).

  - CVE-2018-1124: Prevent multiple integer overflows leading to a heap
  corruption in file2strvec function. This allowed a privilege escalation
  for a local attacker who can create entries in procfs by starting
  processes, which could result in crashes or arbitrary code execution in
  proc utilities run by
  other users (bsc#1092100).

  - CVE-2018-1125: Prevent stack buffer overflow in pgrep. This
  vulnerability was mitigated by FORTIFY limiting the impact to a crash
  (bsc#1092100).

  - CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
  truncation/integer overflow issues (bsc#1092100).


  Also this non-security issue was fixed:

  - Fix CPU summary showing old data. (bsc#1121753)

  The update to 3.3.15 contains the following fixes:

  * library: Increment to 8:0:1 No removals, no new functions Changes: slab
  and pid structures

  * library: Just check for SIGLOST and don't delete it

  * library: Fix integer overflow and LPE in file2strvec   CVE-2018-1124

  * library: Use size_t for alloc functions                CVE-2018-1126

  * library: Increase comm size to 64

  * pgrep: Fix stack-based buffer overflow                 CVE-2018-1125

  * pgrep: Remove >15 warning as comm can be longer

  * ps: Fix buffer overflow in output buffer, causing DOS  CVE-2018-1123

  * ps: Increase command name selection field to 64

  * top: Don't use cwd for location of config              CVE-2018-1122

  * update translations

  * library: build on non-glibc systems

  * free: fix scaling on 32-bit systems

  * Revert 'Support running with child namespaces'

  * library: Increment to 7:0:1 No changes, no removals New functions:
  numa_init, numa_max_node, numa_node_of_cpu, numa_uninit,
  xalloc_err_handler

  * doc: Document I idle state in ps.1 and top.1

  * free: fix some of the SI multiples

  * kill: -l space between name parses correctly

  * library: don't use vm_min_free on non Linux

  * library: don't st ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'procps' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~lp150.5.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
