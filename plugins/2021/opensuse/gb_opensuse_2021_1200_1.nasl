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
  script_oid("1.3.6.1.4.1.25623.1.0.854108");
  script_version("2021-09-03T10:01:28+0000");
  script_cve_id("CVE-2018-14679", "CVE-2018-14681", "CVE-2018-14682");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 11:45:00 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-08-26 03:02:11 +0000 (Thu, 26 Aug 2021)");
  script_name("openSUSE: Security Advisory for libmspack (openSUSE-SU-2021:1200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1200-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CB3MRNYWFKRQUSWOFW43J2YAPXGFTDWP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmspack'
  package(s) announced via the openSUSE-SU-2021:1200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmspack fixes the following issues:

  - CVE-2018-14681: Bad KWAJ file header extensions could cause a one or two
       byte overwrite. (bsc#1103032)

  - CVE-2018-14682: There is an off-by-one error in the TOLOWER() macro for
       CHM decompression. (bsc#1103032)

  - CVE-2018-14679: There is an off-by-one error in the CHM PMGI/PMGL chunk
       number validity checks, which could lead to denial of service.
       (bsc#1103032)

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'libmspack' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmspack-debugsource", rpm:"libmspack-debugsource~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack-devel", rpm:"libmspack-devel~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0", rpm:"libmspack0~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0-debuginfo", rpm:"libmspack0-debuginfo~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mspack-tools", rpm:"mspack-tools~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mspack-tools-debuginfo", rpm:"mspack-tools-debuginfo~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0-32bit", rpm:"libmspack0-32bit~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0-32bit-debuginfo", rpm:"libmspack0-32bit-debuginfo~0.6~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
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