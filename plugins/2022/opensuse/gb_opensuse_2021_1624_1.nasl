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
  script_oid("1.3.6.1.4.1.25623.1.0.854456");
  script_version("2022-02-22T06:48:08+0000");
  script_cve_id("CVE-2020-36129", "CVE-2020-36130", "CVE-2020-36131", "CVE-2020-36135");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 08:16:26 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for libaom (openSUSE-SU-2021:1624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1624-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KMK3AKW3Y2J574OXHVFX4QFELTEHM6MR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libaom'
  package(s) announced via the openSUSE-SU-2021:1624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libaom fixes the following issues:

  - CVE-2020-36129: Fixed stack buffer overflow via the component
       src/aom_image.c (bsc#1193356).

  - CVE-2020-36131: Fixed stack buffer overflow via the component
       stats/rate_hist.c (bsc#1193365).

  - CVE-2020-36135: Fixed NULL pointer dereference via the component
       rate_hist.c (bsc#1193366).

  - CVE-2020-36130: Fixed NULL pointer dereference via the component
       av1/av1_dx_iface.c (bsc#1193369).
  This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'libaom' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"aom-tools", rpm:"aom-tools~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-tools-debuginfo", rpm:"aom-tools-debuginfo~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-debugsource", rpm:"libaom-debugsource~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel", rpm:"libaom-devel~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom0", rpm:"libaom0~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom0-debuginfo", rpm:"libaom0-debuginfo~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel-doc", rpm:"libaom-devel-doc~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom0-32bit", rpm:"libaom0-32bit~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom0-32bit-debuginfo", rpm:"libaom0-32bit-debuginfo~1.0.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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