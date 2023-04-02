# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0102");
  script_cve_id("CVE-2023-1017", "CVE-2023-1018");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 02:04:00 +0000 (Fri, 10 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0102");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0102.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31651");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5933-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4WEJNRD36D3EOCZVXKGPDSJXA35DPPSE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtpms' package(s) announced via the MGASA-2023-0102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write vulnerability exists in TPM2.0's Module Library
allowing writing of a 2-byte data past the end of TPM2.0 command in the
CryptParameterDecryption routine. An attacker who can successfully exploit
this vulnerability can lead to denial of service (crashing the TPM
chip/process or rendering it unusable) and/or arbitrary code execution in
the TPM context. (CVE-2023-1017)
An out-of-bounds read vulnerability exists in TPM2.0's Module Library
allowing a 2-byte read past the end of a TPM2.0 command in the
CryptParameterDecryption routine. An attacker who can successfully exploit
this vulnerability can read or access sensitive data stored in the TPM.
(CVE-2023-1018)");

  script_tag(name:"affected", value:"'libtpms' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tpms-devel", rpm:"lib64tpms-devel~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tpms0", rpm:"lib64tpms0~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpms", rpm:"libtpms~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpms-devel", rpm:"libtpms-devel~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpms0", rpm:"libtpms0~0.9.6~1.mga8", rls:"MAGEIA8"))) {
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
