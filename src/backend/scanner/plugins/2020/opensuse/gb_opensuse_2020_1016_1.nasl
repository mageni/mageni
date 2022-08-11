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
  script_oid("1.3.6.1.4.1.25623.1.0.853295");
  script_version("2020-07-24T07:28:01+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-21 03:02:22 +0000 (Tue, 21 Jul 2020)");
  script_name("openSUSE: Security Advisory for mumble (openSUSE-SU-2020:1016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1016-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mumble'
  package(s) announced via the openSUSE-SU-2020:1016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mumble fixes the following issues:

  mumble was updated 1.3.2:

  * client: Fixed overlay not starting

  Update to upstream version 1.3.1

  - Security

  * Fixed: Potential exploit in the OCB2 encryption (#4227) boo#1174041

  - ICE

  * Fixed: Added missing UserKDFIterations field to UserInfo => Prevents
  getRegistration() from failing with enumerator
  out of range error (#3835)

  - GRPC

  * Fixed: Segmentation fault during murmur shutdown (#3938)

  - Client

  * Fixed: Crash when using multiple monitors (#3756)

  * Fixed: Don't send empty message from clipboard via shortcut, if
  clipboard is empty (#3864)

  * Fixed: Talking indicator being able to freeze to indicate talking when
  self-muted (#4006)

  * Fixed: High CPU usage for update-check if update server not available
  (#4019)

  * Fixed: DBus getCurrentUrl returning empty string when not in
  root-channel (#4029)

  * Fixed: Small parts of whispering leaking out (#4051)

  * Fixed: Last audio frame of normal talking is sent to last whisper
  target (#4050)

  * Fixed: LAN-icon not found in ConnectDialog (#4058)

  * Improved: Set maximal vertical size for User Volume Adjustment dialog
  (#3801)

  * Improved: Don't send empty data to PulseAudio (#3316)

  * Improved: Use the SRV resolved port for UDP connections (#3820)

  * Improved: Manual Plugin UI (#3919)

  * Improved: Don't start Jack server by default (#3990)

  * Improved: Overlay doesn't hook into all other processes by default
  (#4041)

  * Improved: Wait longer before disconnecting from a server due to
  unanswered Ping-messages (#4123)

  - Server

  * Fixed: Possibility to circumvent max user-count in channel (#3880)

  * Fixed: Rate-limit implementation susceptible to time-underflow (#4004)

  * Fixed: OpenSSL error 140E0197 with Qt >= 5.12.2 (#4032)

  * Fixed: VersionCheck for SQL for when to use the WAL feature (#4163)

  * Fixed: Wrong database encoding that could lead to server-crash (#4220)

  * Fixed: DB crash due to primary key violation (now performs 'UPSERT' to
  avoid this) (#4105)

  * Improved: The fields in the Version ProtoBuf message are now
  size-restricted (#4101)

  - use the 'profile profilename /path/to/binary' syntax to make 'ps aufxZ'
  more readable


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1016=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1016=1");

  script_tag(name:"affected", value:"'mumble' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debuginfo", rpm:"mumble-debuginfo~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debugsource", rpm:"mumble-debugsource~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server-debuginfo", rpm:"mumble-server-debuginfo~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit", rpm:"mumble-32bit~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit-debuginfo", rpm:"mumble-32bit-debuginfo~1.3.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debuginfo", rpm:"mumble-debuginfo~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debugsource", rpm:"mumble-debugsource~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server-debuginfo", rpm:"mumble-server-debuginfo~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit", rpm:"mumble-32bit~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit-debuginfo", rpm:"mumble-32bit-debuginfo~1.3.2~lp151.4.12.1", rls:"openSUSELeap15.1"))) {
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