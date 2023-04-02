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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0092");
  script_cve_id("CVE-2022-1941", "CVE-2022-3171");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 17:28:00 +0000 (Thu, 13 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0092)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0092");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0092.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30906");
  script_xref(name:"URL", value:"https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-8gq9-2x98-w8hf");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012857.html");
  script_xref(name:"URL", value:"https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-h4h5-3hr4-j3g2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/R2AEGDIGMLKPLFNJRJWFW4RS6QWEK2NB/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5769-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CBAUKJQL6O4TIWYBENORSY5P43TVB4M3/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5945-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'protobuf' package(s) announced via the MGASA-2023-0092 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Parsing vulnerability for the MessageSet type in the ProtocolBuffers for
protobuf-python can lead to out of memory can lead to a Denial of Service
against services receiving unsanitized input. (CVE-2022-1941)
A parsing issue with binary data in protobuf-java core and lite can lead
to a denial of service attack with crafted input. (CVE-2022-3171)");

  script_tag(name:"affected", value:"'protobuf' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64protobuf-devel", rpm:"lib64protobuf-devel~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64protobuf-lite25", rpm:"lib64protobuf-lite25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64protobuf-static-devel", rpm:"lib64protobuf-static-devel~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64protobuf25", rpm:"lib64protobuf25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64protoc25", rpm:"lib64protoc25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-devel", rpm:"libprotobuf-devel~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25", rpm:"libprotobuf-lite25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-static-devel", rpm:"libprotobuf-static-devel~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25", rpm:"libprotobuf25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25", rpm:"libprotoc25~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf", rpm:"protobuf~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-bom", rpm:"protobuf-bom~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-compiler", rpm:"protobuf-compiler~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java", rpm:"protobuf-java~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java-util", rpm:"protobuf-java-util~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-javadoc", rpm:"protobuf-javadoc~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-javalite", rpm:"protobuf-javalite~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-parent", rpm:"protobuf-parent~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-vim", rpm:"protobuf-vim~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-protobuf", rpm:"python3-protobuf~3.14.0~1.2.mga8", rls:"MAGEIA8"))) {
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
