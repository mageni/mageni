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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0026");
  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2019-19480", "CVE-2019-19481", "CVE-2019-6502");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0026");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0026.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25975");
  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/releases/tag/0.20.0");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/12/29/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the MGASA-2020-0026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated opensc packages fix security vulnerabilities:

sc_context_create in ctx.c in libopensc in OpenSC 0.19.0 has a memory
leak, as demonstrated by a call from eidenv (CVE-2019-6502).

OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Bitstring
in decode_bit_string in libopensc/asn1.c (CVE-2019-15945).

OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Octet
string in asn1_decode_entry in libopensc/asn1.c (CVE-2019-15946).

An issue was discovered in OpenSC through 0.19.0 and 0.20.x through
0.20.0-rc3. libopensc/card-setcos.c has an incorrect read operation during
parsing of a SETCOS file attribute (CVE-2019-19479).

An issue was discovered in OpenSC through 0.19.0 and 0.20.x through
0.20.0-rc3. libopensc/pkcs15-prkey.c has an incorrect free operation in
sc_pkcs15_decode_prkdf_entry (CVE-2019-19480).

An issue was discovered in OpenSC through 0.19.0 and 0.20.x through
0.20.0-rc3. libopensc/card-cac1.c mishandles buffer limits for CAC
certificates (CVE-2019-19481).

The opensc package has been updated to version 0.20.0, which has fixes for
these issues and other improvements.");

  script_tag(name:"affected", value:"'opensc' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc-devel", rpm:"lib64opensc-devel~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc6", rpm:"lib64opensc6~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smm-local6", rpm:"lib64smm-local6~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc-devel", rpm:"libopensc-devel~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc6", rpm:"libopensc6~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmm-local6", rpm:"libsmm-local6~0.20.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.20.0~1.mga7", rls:"MAGEIA7"))) {
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
