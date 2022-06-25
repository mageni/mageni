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
  script_oid("1.3.6.1.4.1.25623.1.0.854671");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2018-20482", "CVE-2019-9923", "CVE-2021-20193");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:08:05 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for tar (SUSE-SU-2022:1548-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1548-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/INEJ3DHWSEUMTE45WNDFF4RSSFHBATKT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tar'
  package(s) announced via the SUSE-SU-2022:1548-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tar fixes the following issues:

  - CVE-2021-20193: Fixed a memory leak in read_header() in list.c
       (bsc#1181131).

  - CVE-2019-9923: Fixed a null-pointer dereference in pax_decode_header in
       sparse.c (bsc#1130496).

  - CVE-2018-20482: Fixed infinite read loop in sparse_dump_region in
       sparse.c (bsc#1120610).

  - Update to GNU tar 1.34:

  * Fix extraction over pipe

  * Fix memory leak in read_header (CVE-2021-20193) (bsc#1181131)

  * Fix extraction when . and .. are unreadable

  * Gracefully handle duplicate symlinks when extracting

  * Re-initialize supplementary groups when switching to user privileges

  - Update to GNU tar 1.33:

  * POSIX extended format headers do not include PID by default

  * --delay-directory-restore works for archives with reversed member
         ordering

  * Fix extraction of a symbolic link hardlinked to another symbolic link

  * Wildcards in exclude-vcs-ignore mode don't match slash

  * Fix the --no-overwrite-dir option

  * Fix handling of chained renames in incremental backups

  * Link counting works for file names supplied with -T

  * Accept only position-sensitive (file-selection) options in file list
         files

  - prepare usrmerge (bsc#1029961)

  - Update to GNU 1.32

  * Fix the use of --checkpoint without explicit --checkpoint-action

  * Fix extraction with the -U option

  * Fix iconv usage on BSD-based systems

  * Fix possible NULL dereference (savannah bug #55369) [bsc#1130496]
         [CVE-2019-9923]

  * Improve the testsuite

  - Update to GNU 1.31

  * Fix heap-buffer-overrun with --one-top-level, bug introduced with the
         addition of that option in 1.28

  * Support for zstd compression

  * New option '--zstd' instructs tar to use zstd as compression program.
         When listing, extractng and comparing, zstd compressed archives are
         recognized automatically. When '-a' option is in effect, zstd
         compression is selected if the destination archive name ends in '.zst'
         or '.tzst'.

  * The -K option interacts properly with member names given in the
         command line. Names of members to extract can be specified along with
         the '-K NAME' option. In this case, tar will extract NAME and those of
         named members that appear in the archive after it, which is consistent
         with the semantics of the option. Previous versions of tar extracted
         NAME, those of named members that appeared before it, and everything
         after it.

  * Fix ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'tar' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"tar", rpm:"tar~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-debuginfo", rpm:"tar-debuginfo~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-debugsource", rpm:"tar-debugsource~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-rmt", rpm:"tar-rmt~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-rmt-debuginfo", rpm:"tar-rmt-debuginfo~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-tests", rpm:"tar-tests~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-tests-debuginfo", rpm:"tar-tests-debuginfo~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-backup-scripts", rpm:"tar-backup-scripts~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-doc", rpm:"tar-doc~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tar-lang", rpm:"tar-lang~1.34~150000.3.12.1", rls:"openSUSELeap15.3"))) {
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