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
  script_oid("1.3.6.1.4.1.25623.1.0.854400");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-4140", "CVE-2022-22737", "CVE-2022-22738", "CVE-2022-22739", "CVE-2022-22740", "CVE-2022-22741", "CVE-2022-22742", "CVE-2022-22743", "CVE-2022-22744", "CVE-2022-22745", "CVE-2022-22746", "CVE-2022-22747", "CVE-2022-22748", "CVE-2022-22751");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:35:47 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2022:0199-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0199-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VJHDOBPPHGJWIXDJDMLZUCHBBMTQIEIO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2022:0199-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  - CVE-2021-4140: Fixed Iframe sandbox bypass with XSLT (bsc#1194547).

  - CVE-2022-22737: Fixed race condition when playing audio files
       (bsc#1194547).

  - CVE-2022-22738: Fixed heap-buffer-overflow in blendGaussianBlur
       (bsc#1194547).

  - CVE-2022-22739: Fixed missing throttling on external protocol launch
       dialog (bsc#1194547).

  - CVE-2022-22740: Fixed use-after-free of ChannelEventQueue::mOwner
       (bsc#1194547).

  - CVE-2022-22741: Fixed browser window spoof using fullscreen mode
       (bsc#1194547).

  - CVE-2022-22742: Fixed out-of-bounds memory access when inserting text in
       edit mode (bsc#1194547).

  - CVE-2022-22743: Fixed browser window spoof using fullscreen mode
       (bsc#1194547).

  - CVE-2022-22744: Fixed possible command injection via the 'Copy as curl'
       feature in DevTools (bsc#1194547).

  - CVE-2022-22745: Fixed leaking cross-origin URLs through
       securitypolicyviolation event (bsc#1194547).

  - CVE-2022-22746: Fixed calling into reportValidity could have lead to
       fullscreen window spoof (bsc#1194547).

  - CVE-2022-22747: Fixed crash when handling empty pkcs7
       sequence(bsc#1194547).

  - CVE-2022-22748: Fixed spoofed origin on external protocol launch dialog
       (bsc#1194547).

  - CVE-2022-22751: Fixed memory safety bugs (bsc#1194547).");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.5.0~8.51.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.5.0~8.51.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.5.0~8.51.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.5.0~8.51.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.5.0~8.51.1", rls:"openSUSELeap15.3"))) {
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