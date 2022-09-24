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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0335");
  script_cve_id("CVE-2021-33643", "CVE-2021-33644", "CVE-2021-33645", "CVE-2021-33646");
  script_tag(name:"creation_date", value:"2022-09-19 05:11:13 +0000 (Mon, 19 Sep 2022)");
  script_version("2022-09-19T10:11:35+0000");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-13 00:17:00 +0000 (Sat, 13 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0335)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0335");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0335.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30821");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OD4HEBSTI22FNYKOKK7W3X6ZQE6FV3XC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtar' package(s) announced via the MGASA-2022-0335 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who submits a crafted tar file with size in header struct
being 0 may be able to trigger an calling of malloc(0) for a variable
gnu_longlink, causing an out-of-bounds read. (CVE-2021-33643)

An attacker who submits a crafted tar file with size in header struct
being 0 may be able to trigger an calling of malloc(0) for a variable
gnu_longname, causing an out-of-bounds read. (CVE-2021-33644)

The th_read() function doesn't free a variable t->th_buf.gnu_longlink
after allocating memory, which may cause a memory leak. (CVE-2021-33645)

The th_read() function doesn't free a variable t->th_buf.gnu_longname
after allocating memory, which may cause a memory leak. (CVE-2021-33646)");

  script_tag(name:"affected", value:"'libtar' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tar-devel", rpm:"lib64tar-devel~1.2.20~9.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tar0", rpm:"lib64tar0~1.2.20~9.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtar", rpm:"libtar~1.2.20~9.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtar-devel", rpm:"libtar-devel~1.2.20~9.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtar0", rpm:"libtar0~1.2.20~9.1.mga8", rls:"MAGEIA8"))) {
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
