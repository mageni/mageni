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
  script_oid("1.3.6.1.4.1.25623.1.0.852669");
  script_version("2019-08-20T10:47:01+0000");
  script_cve_id("CVE-2019-11922");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-20 10:47:01 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-20 02:00:58 +0000 (Tue, 20 Aug 2019)");
  script_name("openSUSE Update for zstd openSUSE-SU-2019:1952-1 (zstd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00062.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zstd'
  package(s) announced via the openSUSE-SU-2019:1952_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zstd fixes the following issues:

  - Update to version 1.4.2:

  * bug: Fix bug in zstd-0.5 decoder by @terrelln (#1696)

  * bug: Fix seekable decompression in-memory API by @iburinoc (#1695)

  * bug: Close minor memory leak in CLI by @LeeYoung624 (#1701)

  * misc: Validate blocks are smaller than size limit by @vivekmig (#1685)

  * misc: Restructure source files by @ephiepark (#1679)

  - Update to version 1.4.1:

  * bug: Fix data corruption in niche use cases by @terrelln (#1659)

  * bug: Fuzz legacy modes, fix uncovered bugs by @terrelln (#1593, #1594,
  #1595)

  * bug: Fix out of bounds read by @terrelln (#1590)

  * perf: Improve decode speed by ~7% @mgrice (#1668)

  * perf: Slightly improved compression ratio of level 3 and 4
  (ZSTD_dfast) by @cyan4973 (#1681)

  * perf: Slightly faster compression speed when re-using a context by
  @cyan4973 (#1658)

  * perf: Improve compression ratio for small windowLog by @cyan4973
  (#1624)

  * perf: Faster compression speed in high compression mode for repetitive
  data by @terrelln (#1635)

  * api: Add parameter to generate smaller dictionaries by @tyler-tran
  (#1656)

  * cli: Recognize symlinks when built in C99 mode by @felixhandte (#1640)

  * cli: Expose cpu load indicator for each file on -vv mode by @ephiepark
  (#1631)

  * cli: Restrict read permissions on destination files by @chungy (#1644)

  * cli: zstdgrep: handle -f flag by @felixhandte (#1618)

  * cli: zstdcat: follow symlinks by @vejnar (#1604)

  * doc: Remove extra size limit on compressed blocks by @felixhandte
  (#1689)

  * doc: Fix typo by @yk-tanigawa (#1633)

  * doc: Improve documentation on streaming buffer sizes by @cyan4973
  (#1629)

  * build: CMake: support building with LZ4 @leeyoung624 (#1626)

  * build: CMake: install zstdless and zstdgrep by @leeyoung624 (#1647)

  * build: CMake: respect existing uninstall target by @j301scott (#1619)

  * build: Make: skip multithread tests when built without support by
  @michaelforney (#1620)

  * build: Make: Fix examples/ test target by @sjnam (#1603)

  * build: Meson: rename options out of deprecated namespace by @lzutao
  (#1665)

  * build: Meson: fix build by @lzutao (#1602)

  * build: Visual Studio: don't export symbols in static lib by @scharan
  (#1650)

  * build: Visual Studio: fix linking by @absotively (#1639)

  * build: Fix MinGW-W64 build by @myzhang1029 (#1600)

  * misc: Expand decodecorpus coverage by @ephiepark (#1664)

  - Add baselibs.conf: libarchive gained zstd support and provides

  - 32bit libraries. This means, zstd also needs to provide -32bit libs.

  - Update to new upstream release 1.4.0

  * ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'zstd' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzstd-devel", rpm:"libzstd-devel~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzstd-devel-static", rpm:"libzstd-devel-static~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzstd1", rpm:"libzstd1~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzstd1-debuginfo", rpm:"libzstd1-debuginfo~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zstd", rpm:"zstd~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zstd-debuginfo", rpm:"zstd-debuginfo~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zstd-debugsource", rpm:"zstd-debugsource~1.4.2~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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