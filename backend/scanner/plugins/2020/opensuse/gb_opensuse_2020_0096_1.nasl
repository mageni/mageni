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
  script_oid("1.3.6.1.4.1.25623.1.0.853009");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2020-6609", "CVE-2020-6610", "CVE-2020-6611", "CVE-2020-6612", "CVE-2020-6613", "CVE-2020-6614", "CVE-2020-6615");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:18:40 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for libredwg (openSUSE-SU-2020:0096_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libredwg'
  package(s) announced via the openSUSE-SU-2020:0096_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libredwg fixes the following issues:

  libredwg was updated to release 0.10:

  API breaking changes:

  * Added a new int *isnewp argument to all dynapi utf8text getters, if the
  returned string is freshly malloced or not.

  * removed the UNKNOWN supertype, there are only UNKNOWN_OBJ and
  UNKNOWN_ENT left, with common_entity_data.

  * renamed BLOCK_HEADER.preview_data to preview, preview_data_size to
  preview_size.

  * renamed SHAPE.shape_no to style_id.

  * renamed CLASS.wasazombie to is_zombie.

  Bugfixes:

  * Harmonized INDXFB with INDXF, removed extra src/in_dxfb.c.

  * Fixed encoding of added r2000 AUXHEADER address.

  * Fixed EED encoding from dwgrewrite.

  * Add several checks against [CVE-2020-6609, boo#1160520], [CVE-2020-6610,
  boo#1160522], [CVE-2020-6611, boo#1160523], [CVE-2020-6612,
  boo#1160524], [CVE-2020-6613, boo#1160525], [CVE-2020-6614,
  boo#1160526], [CVE-2020-6615, boo#1160527]


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-96=1");

  script_tag(name:"affected", value:"'libredwg' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libredwg-debuginfo", rpm:"libredwg-debuginfo~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-debugsource", rpm:"libredwg-debugsource~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-devel", rpm:"libredwg-devel~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-tools", rpm:"libredwg-tools~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-tools-debuginfo", rpm:"libredwg-tools-debuginfo~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg0", rpm:"libredwg0~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg0-debuginfo", rpm:"libredwg0-debuginfo~0.10~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
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