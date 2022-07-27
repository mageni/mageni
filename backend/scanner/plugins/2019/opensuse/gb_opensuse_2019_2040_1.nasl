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
  script_oid("1.3.6.1.4.1.25623.1.0.852680");
  script_version("2019-09-05T09:53:24+0000");
  script_cve_id("CVE-2019-15540");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-05 09:53:24 +0000 (Thu, 05 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-01 02:01:05 +0000 (Sun, 01 Sep 2019)");
  script_name("openSUSE Update for libmirage openSUSE-SU-2019:2040-1 (libmirage)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmirage'
  package(s) announced via the openSUSE-SU-2019:2040_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmirage fixes the following issues:

  CVE-2019-15540: The CSO filter in libMirage in CDemu did not validate the
  part size, triggering a heap-based buffer overflow that could lead to root
  access by a local user. [boo#1148087]

  - Update to new upstream release 3.2.2

  * ISO parser: fixed ISO9660/UDF pattern search for sector sizes 2332 and
  2336.

  * ISO parser: added support for Nintendo GameCube and Wii ISO images.

  * Extended medium type guess to distinguish between DVD and BluRay
  images based on length.

  * Removed fabrication of disc structures from the library (moved to
  CDEmu daemon).

  * MDS parser: cleanup of disc structure parsing, fixed the incorrectly
  set structure sizes.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2040=1");

  script_tag(name:"affected", value:"'libmirage' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmirage-data", rpm:"libmirage-data~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-lang", rpm:"libmirage-lang~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-3_2", rpm:"libmirage-3_2~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-3_2-debuginfo", rpm:"libmirage-3_2-debuginfo~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-debuginfo", rpm:"libmirage-debuginfo~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-debugsource", rpm:"libmirage-debugsource~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage-devel", rpm:"libmirage-devel~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage11", rpm:"libmirage11~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmirage11-debuginfo", rpm:"libmirage11-debuginfo~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-libmirage-3_2", rpm:"typelib-1_0-libmirage-3_2~3.2.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
