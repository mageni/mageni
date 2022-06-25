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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0139");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 12:31:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0139)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0139");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0139.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24532");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/03/18/3");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2019-March/005203.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2' package(s) announced via the MGASA-2019-0139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible integer overflow in transport read allows out-of-bounds write.
(CVE-2019-3855)

Possible integer overflow in keyboard interactive handling allows
out-of-bounds write. (CVE-2019-3856)

Possible integer overflow leading to zero-byte allocation and
out-of-bounds write. (CVE-2019-3857)

Possible zero-byte allocation leading to an out-of-bounds read.
(CVE-2019-3858)

Out-of-bounds reads with specially crafted payloads due to unchecked use
of `_libssh2_packet_require` and `_libssh2_packet_requirev`.
(CVE-2019-3859)

Out-of-bounds reads with specially crafted SFTP packets. (CVE-2019-3860)

Out-of-bounds reads with specially crafted SSH packets. (CVE-2019-3861)

Out-of-bounds memory comparison. (CVE-2019-3862)

Integer overflow in user authenticate keyboard interactive allows
out-of-bounds writes. (CVE-2019-3863)");

  script_tag(name:"affected", value:"'libssh2' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh2-devel", rpm:"lib64ssh2-devel~1.7.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh2_1", rpm:"lib64ssh2_1~1.7.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.7.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.7.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_1", rpm:"libssh2_1~1.7.0~2.1.mga6", rls:"MAGEIA6"))) {
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
