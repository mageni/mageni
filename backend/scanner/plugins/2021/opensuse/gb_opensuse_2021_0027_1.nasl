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
  script_oid("1.3.6.1.4.1.25623.1.0.853661");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2017-17784", "CVE-2017-17785", "CVE-2017-17786");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:59:13 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for gimp (openSUSE-SU-2021:0027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0027-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LKBDGMCM5XJOHFKTACI2CEISBTSKVLD3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp'
  package(s) announced via the openSUSE-SU-2021:0027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gimp fixes the following issues:

  - CVE-2017-17784: Fixed an insufficient string validation for input names
       (bsc#1073624).

  - CVE-2017-17785: Fixed an heap-based buffer overflow in FLI import
       (bsc#1073625).

  - CVE-2017-17786: Fixed an out-of-bounds read in TGA (bsc#1073626).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'gimp' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-debuginfo", rpm:"gimp-devel-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa", rpm:"gimp-plugin-aa~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa-debuginfo", rpm:"gimp-plugin-aa-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python", rpm:"gimp-plugins-python~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python-debuginfo", rpm:"gimp-plugins-python-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo", rpm:"libgimp-2_0-0-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo", rpm:"libgimpui-2_0-0-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit", rpm:"libgimp-2_0-0-32bit~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit-debuginfo", rpm:"libgimp-2_0-0-32bit-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit", rpm:"libgimpui-2_0-0-32bit~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit-debuginfo", rpm:"libgimpui-2_0-0-32bit-debuginfo~2.8.22~lp151.5.9.1", rls:"openSUSELeap15.1"))) {
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