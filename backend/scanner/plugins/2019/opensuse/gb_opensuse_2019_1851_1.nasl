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
  script_oid("1.3.6.1.4.1.25623.1.0.852648");
  script_version("2019-08-14T07:16:43+0000");
  script_cve_id("CVE-2019-14744");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-14 07:16:43 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 02:03:08 +0000 (Wed, 14 Aug 2019)");
  script_name("openSUSE Update for kconfig, openSUSE-SU-2019:1851-1 (kconfig, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kconfig, '
  package(s) announced via the openSUSE-SU-2019:1851_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kconfig, kdelibs4 fixes the following issues:

  - CVE-2019-14744: Fixed a command execution by an shell expansion
  (boo#1144600).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1851=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1851=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1851=1

  - SUSE Package Hub for SUSE Linux Enterprise 12:

  zypper in -t patch openSUSE-2019-1851=1");

  script_tag(name:"affected", value:"'kconfig, ' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"kconf_update5", rpm:"kconf_update5~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconf_update5-debuginfo", rpm:"kconf_update5-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconfig-debugsource", rpm:"kconfig-debugsource~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconfig-devel", rpm:"kconfig-devel~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconfig-devel-debuginfo", rpm:"kconfig-devel-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-branding-upstream", rpm:"kdelibs4-branding-upstream~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-core-debuginfo", rpm:"kdelibs4-core-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-debuginfo", rpm:"kdelibs4-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-debugsource", rpm:"kdelibs4-debugsource~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-doc", rpm:"kdelibs4-doc~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-doc-debuginfo", rpm:"kdelibs4-doc-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigCore5", rpm:"libKF5ConfigCore5~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigCore5-debuginfo", rpm:"libKF5ConfigCore5-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigGui5", rpm:"libKF5ConfigGui5~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigGui5-debuginfo", rpm:"libKF5ConfigGui5-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4", rpm:"libkde4~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4-debuginfo", rpm:"libkde4-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4-devel", rpm:"libkde4-devel~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4-devel-debuginfo", rpm:"libkde4-devel-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4", rpm:"libkdecore4~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4-debuginfo", rpm:"libkdecore4-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4-devel", rpm:"libkdecore4-devel~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4-devel-debuginfo", rpm:"libkdecore4-devel-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksuseinstall-devel", rpm:"libksuseinstall-devel~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksuseinstall1", rpm:"libksuseinstall1~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksuseinstall1-debuginfo", rpm:"libksuseinstall1-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-apidocs", rpm:"kdelibs4-apidocs~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigCore5-lang", rpm:"libKF5ConfigCore5-lang~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconfig-devel-32bit", rpm:"kconfig-devel-32bit~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kconfig-devel-32bit-debuginfo", rpm:"kconfig-devel-32bit-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigCore5-32bit", rpm:"libKF5ConfigCore5-32bit~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigCore5-32bit-debuginfo", rpm:"libKF5ConfigCore5-32bit-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigGui5-32bit", rpm:"libKF5ConfigGui5-32bit~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5ConfigGui5-32bit-debuginfo", rpm:"libKF5ConfigGui5-32bit-debuginfo~5.45.0~lp150.2.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4-32bit", rpm:"libkde4-32bit~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde4-32bit-debuginfo", rpm:"libkde4-32bit-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4-32bit", rpm:"libkdecore4-32bit~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore4-32bit-debuginfo", rpm:"libkdecore4-32bit-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksuseinstall1-32bit", rpm:"libksuseinstall1-32bit~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksuseinstall1-32bit-debuginfo", rpm:"libksuseinstall1-32bit-debuginfo~4.14.38~lp150.6.5.1", rls:"openSUSELeap15.0"))) {
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
