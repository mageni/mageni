# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853181");
  script_version("2020-05-29T08:53:11+0000");
  script_cve_id("CVE-2019-14250", "CVE-2019-15847");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 03:00:46 +0000 (Wed, 27 May 2020)");
  script_name("openSUSE: Security Advisory for gcc9 (openSUSE-SU-2020:0716-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc9'
  package(s) announced via the openSUSE-SU-2020:0716-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update includes the GNU Compiler Collection 9.

  This update ships the GCC 9.3 release.

  The base system compiler libraries libgcc_s1, libstdc++6 and others are
  now built by the gcc 9 packages.

  To use it, install 'gcc9' or 'gcc9-c++' or other compiler brands and use
  CC=gcc-9 / CXX=g++-9 during configuration for using it.


  Security issues fixed:

  - CVE-2019-15847: Fixed a miscompilation in the POWER9 back end, that
  optimized multiple calls of the __builtin_darn intrinsic into a single
  call. (bsc#1149145)

  - CVE-2019-14250: Fixed a heap overflow in the LTO linker. (bsc#1142649)

  Non-security issues fixed:

  - Split out libstdc++ pretty-printers into a separate package
  supplementing gdb and the installed runtime. (bsc#1135254)

  - Fixed miscompilation for vector shift on s390. (bsc#1141897)

  - Includes a fix for Internal compiler error when building HepMC
  (bsc#1167898)

  - Includes fix for binutils version parsing

  - Add libstdc++6-pp provides and conflicts to avoid file conflicts with
  same minor version of libstdc++6-pp from gcc10.

  - Add gcc9 autodetect -g at lto link (bsc#1149995)

  - Install go tool buildid for bootstrapping go


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-716=1");

  script_tag(name:"affected", value:"'gcc9' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gcc9-info", rpm:"gcc9-info~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp9", rpm:"cpp9~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp9-debuginfo", rpm:"cpp9-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc9", rpm:"cross-nvptx-gcc9~9.3.1+git1296~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc9-debuginfo", rpm:"cross-nvptx-gcc9-debuginfo~9.3.1+git1296~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc9-debugsource", rpm:"cross-nvptx-gcc9-debugsource~9.3.1+git1296~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib9-devel", rpm:"cross-nvptx-newlib9-devel~9.3.1+git1296~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-32bit", rpm:"gcc9-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9", rpm:"gcc9~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-ada-32bit", rpm:"gcc9-ada-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-ada", rpm:"gcc9-ada~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-ada-debuginfo", rpm:"gcc9-ada-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-c++-32bit", rpm:"gcc9-c++-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-c++", rpm:"gcc9-c++~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-c++-debuginfo", rpm:"gcc9-c++-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-debuginfo", rpm:"gcc9-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-debugsource", rpm:"gcc9-debugsource~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-fortran-32bit", rpm:"gcc9-fortran-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-fortran", rpm:"gcc9-fortran~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-fortran-debuginfo", rpm:"gcc9-fortran-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-go-32bit", rpm:"gcc9-go-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-go", rpm:"gcc9-go~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-go-debuginfo", rpm:"gcc9-go-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc9-locale", rpm:"gcc9-locale~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada9-32bit", rpm:"libada9-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada9-32bit-debuginfo", rpm:"libada9-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada9", rpm:"libada9~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada9-debuginfo", rpm:"libada9-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan5-32bit", rpm:"libasan5-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan5-32bit-debuginfo", rpm:"libasan5-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan5", rpm:"libasan5~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan5-debuginfo", rpm:"libasan5-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo14-32bit", rpm:"libgo14-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo14-32bit-debuginfo", rpm:"libgo14-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo14", rpm:"libgo14~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo14-debuginfo", rpm:"libgo14-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc9-32bit", rpm:"libstdc++6-devel-gcc9-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc9", rpm:"libstdc++6-devel-gcc9~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc9-32bit", rpm:"libstdc++6-pp-gcc9-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc9", rpm:"libstdc++6-pp-gcc9~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0", rpm:"libtsan0~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0-debuginfo", rpm:"libtsan0-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~9.3.1+git1296~lp151.2.2", rls:"openSUSELeap15.1"))) {
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
