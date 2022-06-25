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
  script_oid("1.3.6.1.4.1.25623.1.0.853364");
  script_version("2020-08-22T03:18:32+0000");
  script_cve_id("CVE-2020-15396", "CVE-2020-15397");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 10:45:32 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-15 03:01:02 +0000 (Sat, 15 Aug 2020)");
  script_name("openSUSE: Security Advisory for hylafax+ (openSUSE-SU-2020:1210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1210-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hylafax+'
  package(s) announced via the openSUSE-SU-2020:1210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hylafax+ fixes the following issues:

  Hylafax was updated to upstream version 7.0.3.

  Security issues fixed:

  - CVE-2020-15396: Secure temporary directory creation for faxsetup,
  faxaddmodem, and probemodem (boo#1173521).

  - CVE-2020-15397: Sourcing of files into binaries from user writeable
  directories (boo#1173519).

  Non-security issues fixed:

  * add UseSSLFax feature in sendfax, sendfax.conf, hyla.conf, and
  JobControl (31 Jul 2020)

  * be more resilient in listening for the Phase C carrier (30 Jul 2020)

  * make sure to return to command mode if HDLC receive times out (29 Jul
  2020)

  * make faxmail ignore boundaries on parts other than multiparts (29 Jul
  2020)

  * don't attempt to write zero bytes of data to a TIFF (29 Jul 2020)

  * don't ever respond to CRP with CRP (28 Jul 2020)

  * reset frame counter when a sender retransmits PPS for a previously
  confirmed ECM block (26 Jul 2020)

  * scrutinize PPM before concluding that the sender missed our MCF (23 Jul
  2020)

  * fix modem recovery after SSL Fax failure (22, 26 Jul 2020)

  * ignore echo of PPR, RTN, CRP (10, 13, 21 Jul 2020)

  * attempt to handle NSF/CSI/DIS in Class 1 sending Phase D (6 Jul 2020)

  * run scripts directly rather than invoking them via a shell for security
  hardening (3-5 Jul 2020)

  * add senderFumblesECM feature (3 Jul 2020)

  * add support for PIN/PIP/PRI-Q/PPS-PRI-Q signals, add senderConfusesPIN
  feature, and utilize PIN for rare conditions where it may be helpful (2,
  6, 13-14 Jul 2020)

  * add senderConfusesRTN feature (25-26 Jun 2020)

  * add MissedPageHandling feature (24 Jun 2020)

  * use and handle CFR in Phase D to retransmit Phase C (16, 23 Jun 2020)

  * cope with hearing echo of RR, CTC during Class 1 sending (15-17 Jun 2020)

  * fix listening for retransmission of MPS/EOP/EOM if it was received
  corrupt on the first attempt (15 Jun 2020)

  * don't use CRP when receiving PPS/PPM as some senders think we are
  sending MCF (12 Jun 2020)

  * add BR_SSLFAX to show SSL Fax in notify and faxinfo output (1 Jun 2020)

  * have faxinfo put units on non-standard page dimensions (28 May 2020)

  * improve error messages for JobHost connection errors (22 May 2020)

  * fix perpetual blocking of jobs when a job preparation fails, attempt to
  fix similar blocking problems for bad jobs in batches, and add 'unblock'
  faxconfig feature (21 May 2020)

  * ignore TCF if we're receiving an SSL Fax (31 Jan 2020)

  * fixes for build on FreeBSD 12.1 (31 Jan - 3 Feb 2020)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1210=1");

  script_tag(name:"affected", value:"'hylafax+' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"hylafax+", rpm:"hylafax+~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client", rpm:"hylafax+-client~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client-debuginfo", rpm:"hylafax+-client-debuginfo~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debuginfo", rpm:"hylafax+-debuginfo~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debugsource", rpm:"hylafax+-debugsource~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil7_0_3", rpm:"libfaxutil7_0_3~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil7_0_3-debuginfo", rpm:"libfaxutil7_0_3-debuginfo~7.0.3~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
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