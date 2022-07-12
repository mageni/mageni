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
  script_oid("1.3.6.1.4.1.25623.1.0.852989");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2019-20009", "CVE-2019-20010", "CVE-2019-20011", "CVE-2019-20012", "CVE-2019-20013", "CVE-2019-20014", "CVE-2019-20015", "CVE-2019-9770", "CVE-2019-9771", "CVE-2019-9772", "CVE-2019-9773", "CVE-2019-9774", "CVE-2019-9775", "CVE-2019-9776", "CVE-2019-9777", "CVE-2019-9778", "CVE-2019-9779");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:17:02 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for libredwg (openSUSE-SU-2020:0068_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libredwg'
  package(s) announced via the openSUSE-SU-2020:0068_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libredwg fixes the following issues:

  libredwg was updated to release 0.9.3:

  * Added the -x, --extnames option to dwglayers for r13-r14 DWGs.

  * Fixed some leaks: SORTENTSTABLE, PROXY_ENTITY.ownerhandle for r13.

  * Add DICTIONARY.itemhandles[] for r13 and r14.

  * Fixed some dwglayers null pointer derefs, and flush its output for each
  layer.

  * Added several overflow checks from fuzzing [CVE-2019-20010,
  boo#1159825], [CVE-2019-20011, boo#1159826], [CVE-2019-20012,
  boo#1159827], [CVE-2019-20013, boo#1159828], [CVE-2019-20014,
  boo#1159831], [CVE-2019-20015, boo#1159832]

  * Disallow illegal SPLINE scenarios [CVE-2019-20009, boo#1159824]

  Update to release 0.9.1:

  * Fixed more null pointer dereferences, overflows, hangs and memory leaks
  for fuzzed (i.e. illegal) DWGs.

  Update to release 0.9 [boo#1154080]:

  * Added the DXF importer, using the new dynapi and the r2000 encoder. Only
  for r2000 DXFs.

  * Added utf8text conversion functions to the dynapi.

  * Added 3DSOLID encoder.

  * Added APIs to find handles for names, searching in tables and dicts.

  * API breaking changes - see NEWS file in package.

  * Fixed null pointer dereferences, and memory leaks (except DXF importer)
  [boo#1129868, CVE-2019-9779] [boo#1129869, CVE-2019-9778] [boo#1129870,
  CVE-2019-9777] [boo#1129873, CVE-2019-9776] [boo#1129874, CVE-2019-9773]
  [boo#1129875, CVE-2019-9772] [boo#1129876, CVE-2019-9771] [boo#1129878,
  CVE-2019-9775] [boo#1129879, CVE-2019-9774] [boo#1129881, CVE-2019-9770]

  Update to 0.8:

  * add a new dynamic API, read and write all header and object fields by
  name

  * API breaking changes

  * Fix many errors in DXF output

  * Fix JSON output

  * Many more bug fixes to handle specific object types


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-68=1");

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

  if(!isnull(res = isrpmvuln(pkg:"libredwg-debuginfo", rpm:"libredwg-debuginfo~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-debugsource", rpm:"libredwg-debugsource~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-devel", rpm:"libredwg-devel~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-tools", rpm:"libredwg-tools~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg-tools-debuginfo", rpm:"libredwg-tools-debuginfo~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg0", rpm:"libredwg0~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libredwg0-debuginfo", rpm:"libredwg0-debuginfo~0.9.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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