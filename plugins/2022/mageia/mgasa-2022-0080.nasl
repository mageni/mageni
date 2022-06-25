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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0080");
  script_cve_id("CVE-2021-4115");
  script_tag(name:"creation_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_version("2022-02-23T03:14:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0080");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0080.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30066");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/02/18/1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2007534");
  script_xref(name:"URL", value:"https://securitylab.github.com/advisories/GHSL-2021-077-polkit/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D6R7S5GYVKZ4LZLTJ5KNEDZRGJISXBAZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/KLISGPPFV5UH2W72SRUBNVWZWI7CWAAY/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit' package(s) announced via the MGASA-2022-0080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a file descriptor leak in polkit, which can enable an
unprivileged user to cause polkit to crash, due to file descriptor
exhaustion. (CVE-2021-4115)");

  script_tag(name:"affected", value:"'polkit' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit-gir1.0", rpm:"lib64polkit-gir1.0~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1-devel", rpm:"lib64polkit1-devel~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1_0", rpm:"lib64polkit1_0~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gir1.0", rpm:"libpolkit-gir1.0~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1-devel", rpm:"libpolkit1-devel~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1_0", rpm:"libpolkit1_0~0.118~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.118~1.3.mga8", rls:"MAGEIA8"))) {
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
