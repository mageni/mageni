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
  script_oid("1.3.6.1.4.1.25623.1.0.853746");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-13428", "CVE-2020-26664");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:34 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for vlc (openSUSE-SU-2021:0076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0076-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OD6C4CTIQTZF237437FPGD5AIRV33TET");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the openSUSE-SU-2021:0076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vlc fixes the following issues:

     Update to 3.0.11.1:

  - CVE-2020-13428: Fixed heap-based buffer overflow in the
       hxxx_AnnexB_to_xVC () (boo#1172727)

  - CVE-2020-26664: Fixed heap-based buffer overflow in
       EbmlTypeDispatcher:send () (boo#1180755)");

  script_tag(name:"affected", value:"'vlc' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"vlc-lang", rpm:"vlc-lang~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5-debuginfo", rpm:"libvlc5-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9-debuginfo", rpm:"libvlccore9-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer", rpm:"vlc-codec-gstreamer~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer-debuginfo", rpm:"vlc-codec-gstreamer-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debuginfo", rpm:"vlc-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-debugsource", rpm:"vlc-debugsource~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack", rpm:"vlc-jack~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack-debuginfo", rpm:"vlc-jack-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX-debuginfo", rpm:"vlc-noX-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv", rpm:"vlc-opencv~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv-debuginfo", rpm:"vlc-opencv-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt-debuginfo", rpm:"vlc-qt-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau", rpm:"vlc-vdpau~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau-debuginfo", rpm:"vlc-vdpau-debuginfo~3.0.11.1~lp151.6.12.1", rls:"openSUSELeap15.1"))) {
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