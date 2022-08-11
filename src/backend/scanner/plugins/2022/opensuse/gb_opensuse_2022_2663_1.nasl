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
  script_oid("1.3.6.1.4.1.25623.1.0.854879");
  script_version("2022-08-10T10:11:40+0000");
  script_cve_id("CVE-2022-33068");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 17:16:00 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-08-05 01:01:53 +0000 (Fri, 05 Aug 2022)");
  script_name("openSUSE: Security Advisory for harfbuzz (SUSE-SU-2022:2663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2663-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EZG2O5OLX6SWWFIQJLLC6U6BDKLWINWQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'harfbuzz'
  package(s) announced via the SUSE-SU-2022:2663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for harfbuzz fixes the following issues:

  - CVE-2022-33068: Fixed a integer overflow in hb-ot-shape-fallback.cc
       (bsc#1200900).");

  script_tag(name:"affected", value:"'harfbuzz' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-debugsource", rpm:"harfbuzz-debugsource~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-devel", rpm:"harfbuzz-devel~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-tools", rpm:"harfbuzz-tools~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-tools-debuginfo", rpm:"harfbuzz-tools-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-gobject0", rpm:"libharfbuzz-gobject0~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-gobject0-debuginfo", rpm:"libharfbuzz-gobject0-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0", rpm:"libharfbuzz-icu0~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-debuginfo", rpm:"libharfbuzz-icu0-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-subset0", rpm:"libharfbuzz-subset0~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-subset0-debuginfo", rpm:"libharfbuzz-subset0-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0", rpm:"libharfbuzz0~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo", rpm:"libharfbuzz0-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-HarfBuzz-0_0", rpm:"typelib-1_0-HarfBuzz-0_0~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-gobject0-32bit", rpm:"libharfbuzz-gobject0-32bit~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-gobject0-32bit-debuginfo", rpm:"libharfbuzz-gobject0-32bit-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-32bit", rpm:"libharfbuzz-icu0-32bit~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-32bit-debuginfo", rpm:"libharfbuzz-icu0-32bit-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-subset0-32bit", rpm:"libharfbuzz-subset0-32bit~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-subset0-32bit-debuginfo", rpm:"libharfbuzz-subset0-32bit-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-32bit", rpm:"libharfbuzz0-32bit~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-32bit-debuginfo", rpm:"libharfbuzz0-32bit-debuginfo~2.6.4~150200.3.3.1", rls:"openSUSELeap15.3"))) {
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