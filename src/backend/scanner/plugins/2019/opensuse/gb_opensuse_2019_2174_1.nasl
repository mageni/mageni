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
  script_oid("1.3.6.1.4.1.25623.1.0.852709");
  script_version("2019-09-27T07:41:55+0000");
  script_cve_id("CVE-2019-14822");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-27 07:41:55 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-25 02:01:27 +0000 (Wed, 25 Sep 2019)");
  script_name("openSUSE Update for ibus openSUSE-SU-2019:2174-1 (ibus)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00056.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ibus'
  package(s) announced via the openSUSE-SU-2019:2174_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ibus fixes the following issues:

  Security issue fixed:

  - CVE-2019-14822: Fixed a misconfiguration of the DBus server that allowed
  an unprivileged user to monitor and send method calls to the ibus bus of
  another user. (bsc#1150011)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2174=1");

  script_tag(name:"affected", value:"'ibus' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"ibus", rpm:"ibus~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-debuginfo", rpm:"ibus-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-debugsource", rpm:"ibus-debugsource~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-devel", rpm:"ibus-devel~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk", rpm:"ibus-gtk~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk-debuginfo", rpm:"ibus-gtk-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3", rpm:"ibus-gtk3~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3-debuginfo", rpm:"ibus-gtk3-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-1_0-5", rpm:"libibus-1_0-5~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-1_0-5-debuginfo", rpm:"libibus-1_0-5-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-ibus", rpm:"python-ibus~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-IBus-1_0", rpm:"typelib-1_0-IBus-1_0~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-branding-openSUSE-KDE", rpm:"ibus-branding-openSUSE-KDE~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-lang", rpm:"ibus-lang~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk-32bit", rpm:"ibus-gtk-32bit~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk-32bit-debuginfo", rpm:"ibus-gtk-32bit-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3-32bit", rpm:"ibus-gtk3-32bit~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3-32bit-debuginfo", rpm:"ibus-gtk3-32bit-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-1_0-5-32bit", rpm:"libibus-1_0-5-32bit~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-1_0-5-32bit-debuginfo", rpm:"libibus-1_0-5-32bit-debuginfo~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ibus", rpm:"python3-ibus~1.5.17~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
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
