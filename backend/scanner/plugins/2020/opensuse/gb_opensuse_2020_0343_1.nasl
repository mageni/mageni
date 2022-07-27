# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853071");
  script_version("2020-03-16T11:42:10+0000");
  script_cve_id("CVE-2019-20446");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-03-17 10:20:57 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-16 04:00:27 +0000 (Mon, 16 Mar 2020)");
  script_name("openSUSE: Security Advisory for librsvg (openSUSE-SU-2020:0343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg'
  package(s) announced via the openSUSE-SU-2020:0343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for librsvg to version 2.42.8 fixes the following issues:

  librsvg was updated to version 2.42.8 fixing the following issues:

  - CVE-2019-20446: Fixed an issue where a crafted SVG file with nested
  patterns can cause denial of service (bsc#1162501). NOTE: Librsvg now
  has limits on the number of loaded XML elements, and the number of
  referenced elements within an SVG document.

  - Fixed a stack exhaustion with circular references in <use> elements.

  - Fixed a denial-of-service condition from exponential explosion
  of rendered elements, through nested use of SVG 'use' elements in
  malicious SVGs.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-343=1");

  script_tag(name:"affected", value:"'librsvg' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-debuginfo", rpm:"gdk-pixbuf-loader-rsvg-debuginfo~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-debuginfo", rpm:"librsvg-2-2-debuginfo~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-debugsource", rpm:"librsvg-debugsource~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-devel", rpm:"librsvg-devel~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsvg-view", rpm:"rsvg-view~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsvg-view-debuginfo", rpm:"rsvg-view-debuginfo~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Rsvg-2_0", rpm:"typelib-1_0-Rsvg-2_0~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-32bit", rpm:"gdk-pixbuf-loader-rsvg-32bit~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-32bit-debuginfo", rpm:"gdk-pixbuf-loader-rsvg-32bit-debuginfo~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-32bit", rpm:"librsvg-2-2-32bit~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-32bit-debuginfo", rpm:"librsvg-2-2-32bit-debuginfo~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svg-thumbnailer", rpm:"svg-thumbnailer~2.42.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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