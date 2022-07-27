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
  script_oid("1.3.6.1.4.1.25623.1.0.853341");
  script_version("2020-08-14T06:59:33+0000");
  script_cve_id("CVE-2020-14344");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-08 03:01:27 +0000 (Sat, 08 Aug 2020)");
  script_name("openSUSE: Security Advisory for libX11 (openSUSE-SU-2020:1162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1162-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libX11'
  package(s) announced via the openSUSE-SU-2020:1162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libX11 fixes the following issues:

  - Fixed XIM client heap overflows (CVE-2020-14344, bsc#1174628)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1162=1");

  script_tag(name:"affected", value:"'libX11' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0-debuginfo", rpm:"libxcb-composite0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0-debuginfo", rpm:"libxcb-damage0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-debugsource", rpm:"libxcb-debugsource~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0-debuginfo", rpm:"libxcb-dpms0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0", rpm:"libxcb-dri2-0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-debuginfo", rpm:"libxcb-dri2-0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0", rpm:"libxcb-dri3-0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-debuginfo", rpm:"libxcb-dri3-0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-debuginfo", rpm:"libxcb-glx0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0", rpm:"libxcb-present0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-debuginfo", rpm:"libxcb-present0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0-debuginfo", rpm:"libxcb-randr0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0-debuginfo", rpm:"libxcb-record0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-debuginfo", rpm:"libxcb-render0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0-debuginfo", rpm:"libxcb-res0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0-debuginfo", rpm:"libxcb-screensaver0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0-debuginfo", rpm:"libxcb-shape0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-debuginfo", rpm:"libxcb-shm0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1", rpm:"libxcb-sync1~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-debuginfo", rpm:"libxcb-sync1-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0-debuginfo", rpm:"libxcb-xf86dri0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-debuginfo", rpm:"libxcb-xfixes0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0-debuginfo", rpm:"libxcb-xinerama0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0", rpm:"libxcb-xinput0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0-debuginfo", rpm:"libxcb-xinput0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1", rpm:"libxcb-xkb1~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1-debuginfo", rpm:"libxcb-xkb1-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0-debuginfo", rpm:"libxcb-xtest0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0-debuginfo", rpm:"libxcb-xv0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0-debuginfo", rpm:"libxcb-xvmc0-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-debuginfo", rpm:"libxcb1-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel-doc", rpm:"libxcb-devel-doc~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel-32bit", rpm:"libX11-devel-32bit~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0-32bit", rpm:"libxcb-composite0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0-32bit-debuginfo", rpm:"libxcb-composite0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0-32bit", rpm:"libxcb-damage0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0-32bit-debuginfo", rpm:"libxcb-damage0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel-32bit", rpm:"libxcb-devel-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0-32bit", rpm:"libxcb-dpms0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0-32bit-debuginfo", rpm:"libxcb-dpms0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit", rpm:"libxcb-dri2-0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit-debuginfo", rpm:"libxcb-dri2-0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit", rpm:"libxcb-dri3-0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit-debuginfo", rpm:"libxcb-dri3-0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit", rpm:"libxcb-glx0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit-debuginfo", rpm:"libxcb-glx0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit", rpm:"libxcb-present0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit-debuginfo", rpm:"libxcb-present0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0-32bit", rpm:"libxcb-randr0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0-32bit-debuginfo", rpm:"libxcb-randr0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0-32bit", rpm:"libxcb-record0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0-32bit-debuginfo", rpm:"libxcb-record0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit", rpm:"libxcb-render0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit-debuginfo", rpm:"libxcb-render0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0-32bit", rpm:"libxcb-res0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0-32bit-debuginfo", rpm:"libxcb-res0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0-32bit", rpm:"libxcb-screensaver0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0-32bit-debuginfo", rpm:"libxcb-screensaver0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0-32bit", rpm:"libxcb-shape0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0-32bit-debuginfo", rpm:"libxcb-shape0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit", rpm:"libxcb-shm0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit-debuginfo", rpm:"libxcb-shm0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit", rpm:"libxcb-sync1-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit-debuginfo", rpm:"libxcb-sync1-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0-32bit", rpm:"libxcb-xf86dri0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0-32bit-debuginfo", rpm:"libxcb-xf86dri0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit", rpm:"libxcb-xfixes0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit-debuginfo", rpm:"libxcb-xfixes0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0-32bit", rpm:"libxcb-xinerama0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0-32bit-debuginfo", rpm:"libxcb-xinerama0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0-32bit", rpm:"libxcb-xinput0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0-32bit-debuginfo", rpm:"libxcb-xinput0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1-32bit", rpm:"libxcb-xkb1-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1-32bit-debuginfo", rpm:"libxcb-xkb1-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0-32bit", rpm:"libxcb-xtest0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0-32bit-debuginfo", rpm:"libxcb-xtest0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0-32bit", rpm:"libxcb-xv0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0-32bit-debuginfo", rpm:"libxcb-xv0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0-32bit", rpm:"libxcb-xvmc0-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0-32bit-debuginfo", rpm:"libxcb-xvmc0-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit", rpm:"libxcb1-32bit~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit-debuginfo", rpm:"libxcb1-32bit-debuginfo~1.13~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
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