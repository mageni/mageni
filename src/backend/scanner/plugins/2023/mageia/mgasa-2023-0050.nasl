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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0050");
  script_cve_id("CVE-2023-22745");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-26 20:25:00 +0000 (Thu, 26 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0050");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0050.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31532");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GDNOV2RNQ7XMOQZ3PV7PHYP2FMJHV2AB/");
  script_xref(name:"URL", value:"https://github.com/tpm2-software/tpm2-tss/security/advisories/GHSA-4j3v-fh23-vx67");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2-tss' package(s) announced via the MGASA-2023-0050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tss2_RC_SetHandler and Tss2_RC_Decode both index into layer_handler with
an 8 bit layer number, but the array only has
TPM2_ERROR_TSS2_RC_LAYER_COUNT entries, so trying to add a handler for
higher-numbered layers or decode a response code with such a layer number
reads/writes past the end of the buffer. (CVE-2023-22745)");

  script_tag(name:"affected", value:"'tpm2-tss' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tpm2-tss-devel", rpm:"lib64tpm2-tss-devel~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-esys0", rpm:"lib64tss2-esys0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-fapi1", rpm:"lib64tss2-fapi1~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-mu0", rpm:"lib64tss2-mu0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-rc0", rpm:"lib64tss2-rc0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-sys1", rpm:"lib64tss2-sys1~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-cmd0", rpm:"lib64tss2-tcti-cmd0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-device0", rpm:"lib64tss2-tcti-device0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-mssim0", rpm:"lib64tss2-tcti-mssim0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-pcap0", rpm:"lib64tss2-tcti-pcap0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-swtpm0", rpm:"lib64tss2-tcti-swtpm0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tctildr0", rpm:"lib64tss2-tctildr0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpm2-tss-devel", rpm:"libtpm2-tss-devel~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.2.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-tss", rpm:"tpm2-tss~3.2.2~1.mga8", rls:"MAGEIA8"))) {
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
