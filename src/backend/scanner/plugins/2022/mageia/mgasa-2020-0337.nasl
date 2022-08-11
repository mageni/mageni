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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0337");
  script_cve_id("CVE-2017-13745", "CVE-2017-13746", "CVE-2017-13748", "CVE-2017-13749", "CVE-2017-13750", "CVE-2017-13751", "CVE-2017-14132", "CVE-2017-6851", "CVE-2017-6852", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-19139", "CVE-2018-19543", "CVE-2018-20570", "CVE-2018-20622", "CVE-2018-9252");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-09 23:15:00 +0000 (Fri, 09 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0337");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0337.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27045");
  script_xref(name:"URL", value:"https://github.com/jasper-software/jasper/blob/master/NEWS");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201908-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the MGASA-2020-0337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The jas_matrix_bindsub function in jas_seq.c in JasPer 2.0.10 allows remote
attackers to cause a denial of service (invalid read) via a crafted image
(CVE-2017-6851).

Heap-based buffer overflow in the jpc_dec_decodepkt function in jpc_t2dec.c in
JasPer 2.0.10 allows remote attackers to have unspecified impact via a crafted
image (CVE-2017-6852).

JasPer 2.0.12 allows remote attackers to cause a denial of service (heap-based
buffer over-read and application crash) via a crafted image, related to the
jp2_decode function in libjasper/jp2/jp2_dec.c (CVE-2017-9782).

There is a reachable assertion abort in the function jpc_dec_process_sot() in
jpc/jpc_dec.c in JasPer 2.0.12 that will lead to a remote denial of service
attack by triggering an unexpected jpc_ppmstabtostreams return value (CVE-2017-13745).

There is a reachable assertion abort in the function jpc_dec_process_siz() in
jpc/jpc_dec.c:1297 in JasPer 2.0.12 that will lead to a remote denial of
service attack (CVE-2017-13746).

There are lots of memory leaks in JasPer 2.0.12, triggered in the function
jas_strdup() in base/jas_string.c, that will lead to a remote denial of
service attack (CVE-2017-13748).

There is a reachable assertion abort in the function jpc_pi_nextrpcl() in
jpc/jpc_t2cod.c in JasPer 2.0.12 that will lead to a remote denial of service
attack (CVE-2017-13749).

There is a reachable assertion abort in the function jpc_dec_process_siz() in
jpc/jpc_dec.c:1296 in JasPer 2.0.12 that will lead to a remote denial of
service attack (CVE-2017-13750).

There is a reachable assertion abort in the function calcstepsizes() in
jpc/jpc_dec.c in JasPer 2.0.12 that will lead to a remote denial of service
attack (CVE-2017-13751).

JasPer 2.0.13 allows remote attackers to cause a denial of service (heap-based
buffer over-read and application crash) via a crafted image, related to the
jas_image_ishomosamp function in libjasper/base/jas_image.c (CVE-2017-14132).

JasPer 2.0.14 allows denial of service via a reachable assertion in the
function jpc_abstorelstepsize in libjasper/jpc/jpc_enc.c (CVE-2018-9252).

An issue was discovered in JasPer 2.0.14. There is a NULL pointer dereference
in the function ras_putdatastd in ras/ras_enc.c (CVE-2018-18873).

An issue has been found in JasPer 2.0.14. There is a memory leak in
jas_malloc.c when called from jpc_unk_getparms in jpc_cs.c (CVE-2018-19139).

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer
over-read of size 8 in the function jp2_decode in libjasper/jp2/jp2_dec.c
(CVE-2018-19543).

jp2_encode in jp2/jp2_enc.c in JasPer 2.0.14 has a heap-based buffer over-read
(CVE-2018-20570).

JasPer 2.0.14 has a memory leak in base/jas_malloc.c in libjasper.a when
'--output-format jp2' is used (CVE-2018-20622).");

  script_tag(name:"affected", value:"'jasper' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"jasper", rpm:"jasper~2.0.19~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jasper-devel", rpm:"lib64jasper-devel~2.0.19~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jasper4", rpm:"lib64jasper4~2.0.19~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~2.0.19~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper4", rpm:"libjasper4~2.0.19~1.mga7", rls:"MAGEIA7"))) {
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
