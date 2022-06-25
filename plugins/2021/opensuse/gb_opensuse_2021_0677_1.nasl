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
  script_oid("1.3.6.1.4.1.25623.1.0.853799");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2017-1000369", "CVE-2017-16943", "CVE-2017-16944", "CVE-2018-6789", "CVE-2019-16928", "CVE-2020-12783", "CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28010", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28016", "CVE-2020-28017", "CVE-2020-28018", "CVE-2020-28019", "CVE-2020-28020", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28023", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026", "CVE-2019-15846", "CVE-2019-13917", "CVE-2019-10149");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-08 03:01:00 +0000 (Sat, 08 May 2021)");
  script_name("openSUSE: Security Advisory for exim (openSUSE-SU-2021:0677-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0677-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4UGIR4NXSH3ADTQNJZHHL5EVSFNXRGTQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim'
  package(s) announced via the openSUSE-SU-2021:0677-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exim fixes the following issues:


     Exim was updated to exim-4.94.2

     security update (boo#1185631)

  * CVE-2020-28007: Link attack in Exim&#x27 s log directory

  * CVE-2020-28008: Assorted attacks in Exim&#x27 s spool directory

  * CVE-2020-28014: Arbitrary PID file creation

  * CVE-2020-28011: Heap buffer overflow in queue_run()

  * CVE-2020-28010: Heap out-of-bounds write in main()

  * CVE-2020-28013: Heap buffer overflow in parse_fix_phrase()

  * CVE-2020-28016: Heap out-of-bounds write in parse_fix_phrase()

  * CVE-2020-28015: New-line injection into spool header file (local)

  * CVE-2020-28012: Missing close-on-exec flag for privileged pipe

  * CVE-2020-28009: Integer overflow in get_stdinput()

  * CVE-2020-28017: Integer overflow in receive_add_recipient()

  * CVE-2020-28020: Integer overflow in receive_msg()

  * CVE-2020-28023: Out-of-bounds read in smtp_setup_msg()

  * CVE-2020-28021: New-line injection into spool header file (remote)

  * CVE-2020-28022: Heap out-of-bounds read and write in extract_option()

  * CVE-2020-28026: Line truncation and injection in spool_read_header()

  * CVE-2020-28019: Failure to reset function pointer after BDAT error

  * CVE-2020-28024: Heap buffer underflow in smtp_ungetc()

  * CVE-2020-28018: Use-after-free in tls-openssl.c

  * CVE-2020-28025: Heap out-of-bounds read in pdkim_finish_bodyhash()

     update to exim-4.94.1

  * Fix security issue in BDAT state confusion. Ensure we reset known-good
         where we know we need to not be reading BDAT data, as a general case
         fix, and move the places where we switch to BDAT mode until after
         various protocol state checks. Fixes CVE-2020-BDATA reported by Qualys.

  * Fix security issue in SMTP verb option parsing (CVE-2020-EXOPT)

  * Fix security issue with too many recipients on a message (to remove a
         known security problem if someone does set recipients_max to unlimited,
         or if local additions add to the recipient list). Fixes CVE-2020-RCPTL
          reported by Qualys.

  * Fix CVE-2020-28016 (PFPZA): Heap out-of-bounds write in
         parse_fix_phrase()

  * Fix security issue CVE-2020-PFPSN and guard against cmdline invoker
         providing a particularly obnoxious sender full name.

  * Fix Linux security issue CVE-2020-SLCWD and guard against PATH_MAX
         better.

  - bring back missing exim_db.8 manual page (fixes boo#1173693)

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'exim' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-debuginfo", rpm:"exim-debuginfo~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim-debugsource", rpm:"exim-debugsource~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximon", rpm:"eximon~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximon-debuginfo", rpm:"eximon-debuginfo~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximstats-html", rpm:"eximstats-html~4.94.2~lp152.8.3.1", rls:"openSUSELeap15.2"))) {
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
