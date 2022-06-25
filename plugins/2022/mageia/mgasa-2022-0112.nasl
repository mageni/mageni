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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0112");
  script_cve_id("CVE-2022-23645");
  script_tag(name:"creation_date", value:"2022-03-24 04:13:35 +0000 (Thu, 24 Mar 2022)");
  script_version("2022-03-24T04:13:35+0000");
  script_tag(name:"last_modification", value:"2022-03-24 04:13:35 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 13:49:00 +0000 (Mon, 07 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0112");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0112.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30125");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WL735FW266GO4C2JX4CJBOIOB7R7AY5A/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'swtpm' package(s) announced via the MGASA-2022-0112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"swtpm is a libtpms-based TPM emulator with socket, character device, and
Linux CUSE interface. Versions prior to 0.5.3, 0.6.2, and 0.7.1 are
vulnerable to out-of-bounds read. A specially crafted header of swtpm's
state, where the blobheader's hdrsize indicator has an invalid value, may
cause an out-of-bounds access when the byte array representing the state
of the TPM is accessed. This will likely crash swtpm or prevent it from
starting since the state cannot be understood. Users should upgrade to
swtpm v0.5.3, v0.6.2, or v0.7.1 to receive a patch. There are currently no
known workarounds. (CVE-2022-23645)");

  script_tag(name:"affected", value:"'swtpm' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64wtpm_libtpms-devel", rpm:"lib64wtpm_libtpms-devel~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wtpm_libtpms0", rpm:"lib64wtpm_libtpms0~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwtpm_libtpms-devel", rpm:"libwtpm_libtpms-devel~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwtpm_libtpms0", rpm:"libwtpm_libtpms0~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"swtpm", rpm:"swtpm~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"swtpm-tools", rpm:"swtpm-tools~0.7.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"swtpm-tools-pkcs11", rpm:"swtpm-tools-pkcs11~0.7.1~1.mga8", rls:"MAGEIA8"))) {
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
