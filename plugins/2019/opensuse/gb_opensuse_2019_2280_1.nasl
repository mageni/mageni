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
  script_oid("1.3.6.1.4.1.25623.1.0.852733");
  script_version("2019-10-11T07:39:42+0000");
  script_cve_id("CVE-2019-9893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-11 07:39:42 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-08 02:00:49 +0000 (Tue, 08 Oct 2019)");
  script_name("openSUSE Update for libseccomp openSUSE-SU-2019:2280-1 (libseccomp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libseccomp'
  package(s) announced via the openSUSE-SU-2019:2280_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libseccomp fixes the following issues:

  Security issues fixed:

  - CVE-2019-9893: An incorrect generation of syscall filters in libseccomp
  was fixed (bsc#1128828)

  libseccomp was updated to new upstream release 2.4.1:

  - Fix a BPF generation bug where the optimizer mistakenly identified
  duplicate BPF code blocks.

  libseccomp was updated to 2.4.0 (bsc#1128828 CVE-2019-9893):

  - Update the syscall table for Linux v5.0-rc5

  - Added support for the SCMP_ACT_KILL_PROCESS action

  - Added support for the SCMP_ACT_LOG action and SCMP_FLTATR_CTL_LOG
  attribute

  - Added explicit 32-bit (SCMP_AX_32(...)) and 64-bit (SCMP_AX_64(...))
  argument comparison macros to help protect against unexpected sign
  extension

  - Added support for the parisc and parisc64 architectures

  - Added the ability to query and set the libseccomp API level via
  seccomp_api_get(3) and seccomp_api_set(3)

  - Return -EDOM on an endian mismatch when adding an architecture to a
  filter

  - Renumber the pseudo syscall number for subpage_prot() so it no longer
  conflicts with spu_run()

  - Fix PFC generation when a syscall is prioritized, but no rule exists

  - Numerous fixes to the seccomp-bpf filter generation code

  - Switch our internal hashing function to jhash/Lookup3 to MurmurHash3

  - Numerous tests added to the included test suite, coverage now at ~92%

  - Update our Travis CI configuration to use Ubuntu 16.04

  - Numerous documentation fixes and updates

  libseccomp was updated to release 2.3.3:

  - Updated the syscall table for Linux v4.15-rc7


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2280=1");

  script_tag(name:"affected", value:"'libseccomp' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-debugsource", rpm:"libseccomp-debugsource~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-devel", rpm:"libseccomp-devel~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-tools", rpm:"libseccomp-tools~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-tools-debuginfo", rpm:"libseccomp-tools-debuginfo~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2", rpm:"libseccomp2~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-debuginfo", rpm:"libseccomp2-debuginfo~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit", rpm:"libseccomp2-32bit~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit-debuginfo", rpm:"libseccomp2-32bit-debuginfo~2.4.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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