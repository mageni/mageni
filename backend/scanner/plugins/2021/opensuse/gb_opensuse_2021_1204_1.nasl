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
  script_oid("1.3.6.1.4.1.25623.1.0.854118");
  script_version("2021-09-03T10:01:28+0000");
  script_cve_id("CVE-2020-12049");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:17:00 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-08-27 01:02:02 +0000 (Fri, 27 Aug 2021)");
  script_name("openSUSE: Security Advisory for dbus-1 (openSUSE-SU-2021:1204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1204-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LPUICUYAOLJREPLAWO5JOKCXD4HSH4KT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus-1'
  package(s) announced via the openSUSE-SU-2021:1204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dbus-1 fixes the following issues:

  - CVE-2020-12049: truncated messages lead to resource exhaustion.
       (bsc#1172505)

     This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Special Instructions and Notes:

     Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'dbus-1' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debuginfo", rpm:"dbus-1-debuginfo~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debugsource", rpm:"dbus-1-debugsource~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-devel", rpm:"dbus-1-devel~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debuginfo", rpm:"dbus-1-x11-debuginfo~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debugsource", rpm:"dbus-1-x11-debugsource~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3", rpm:"libdbus-1-3~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-debuginfo", rpm:"libdbus-1-3-debuginfo~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-32bit-debuginfo", rpm:"dbus-1-32bit-debuginfo~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-devel-32bit", rpm:"dbus-1-devel-32bit~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-32bit", rpm:"libdbus-1-3-32bit~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-32bit-debuginfo", rpm:"libdbus-1-3-32bit-debuginfo~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-devel-doc", rpm:"dbus-1-devel-doc~1.12.2~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
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