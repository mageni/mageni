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
  script_oid("1.3.6.1.4.1.25623.1.0.852399");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2018-20544", "CVE-2018-20545", "CVE-2018-20546", "CVE-2018-20547", "CVE-2018-20548", "CVE-2018-20549");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-05 02:00:54 +0000 (Fri, 05 Apr 2019)");
  script_name("openSUSE Update for libcaca openSUSE-SU-2019:1144-1 (libcaca)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca'
  package(s) announced via the openSUSE-SU-2019:1144_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcaca fixes the following issues:

  Security issues fixed:

  - CVE-2018-20544: Fixed a floating point exception at caca/dither.c
  (bsc#1120502)

  - CVE-2018-20545: Fixed a WRITE memory access in the load_image function
  at common-image.c for 4bpp (bsc#1120584)

  - CVE-2018-20546: Fixed a READ memory access in the get_rgba_default
  function at caca/dither.c for bpp (bsc#1120503)

  - CVE-2018-20547: Fixed a READ memory access in the get_rgba_default
  function at caca/dither.c for 24bpp (bsc#1120504)

  - CVE-2018-20548: Fixed a WRITE memory access in the load_image function
  at common-image.c for 1bpp (bsc#1120589)

  - CVE-2018-20549: Fixed a WRITE memory access in the caca_file_read
  function at caca/file.c (bsc#1120470)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1144=1");

  script_tag(name:"affected", value:"'libcaca' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caca-utils-debuginfo", rpm:"caca-utils-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-debugsource", rpm:"libcaca-debugsource~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby", rpm:"libcaca-ruby~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby-debuginfo", rpm:"libcaca-ruby-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-debuginfo", rpm:"libcaca0-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins", rpm:"libcaca0-plugins~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-debuginfo", rpm:"libcaca0-plugins-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit", rpm:"libcaca0-32bit~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit-debuginfo", rpm:"libcaca0-32bit-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit", rpm:"libcaca0-plugins-32bit~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit-debuginfo", rpm:"libcaca0-plugins-32bit-debuginfo~0.99.beta19.git20171003~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
