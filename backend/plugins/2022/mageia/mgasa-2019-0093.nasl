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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0093");
  script_cve_id("CVE-2018-16548", "CVE-2018-17828", "CVE-2018-6381", "CVE-2018-6484", "CVE-2018-6540", "CVE-2018-6541", "CVE-2018-6542", "CVE-2018-6869", "CVE-2018-7725", "CVE-2018-7726", "CVE-2018-7727");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0093.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22570");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/R5NI6QBHJA6ZI7AYP4BYGADTML3F2LNO/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/T5F2Q7GQYRYWHMTEF2OKBIHBBFV6SZBY/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/I6J523IVLVVPUEHRDYT54A5QOKM5XVTO/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MKVLTCQZTM4IO2OP63CRKPLX6NQKLQ2O/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16548");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-02/msg00110.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-06/msg00017.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-10/msg00130.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zziplib' package(s) announced via the MGASA-2019-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ZZIPlib 0.13.67, there is a segmentation fault caused by invalid memory
access in the zzip_disk_fread function (zzip/mmapped.c) because the size
variable is not validated against the amount of file->stored data
(CVE-2018-6381).

An unaligned memory access bug was found in the way ZZIPlib handled ZIP files.
This flaw could potentially be used to crash the application using ZZIPlib by
tricking the application into processing specially crafted ZIP files
(CVE-2018-6484).

In ZZIPlib 0.13.67, there is a bus error caused by loading of a misaligned
address in the zzip_disk_findfirst function of zzip/mmapped.c. Remote
attackers could leverage this vulnerability to cause a denial of service via a
crafted zip file (CVE-2018-6540).

A flaw was found in ZZIPlib 0.13.67, there is a bus error caused by loading of
a misaligned address (when handling disk64_trailer local entries) in
__zzip_fetch_disk_trailer (zzip/zip.c). Remote attackers could leverage this
vulnerability to cause a denial of service via a crafted zip file
(CVE-2018-6541).

In ZZIPlib 0.13.67, there is a bus error (when handling a disk64_trailer seek
value) caused by loading of a misaligned address in the zzip_disk_findfirst
function of zzip/mmapped.c (CVE-2018-6542).

An uncontrolled memory allocation was found in ZZIPlib that could lead to a
crash in the __zzip_parse_root_directory function of zzip/zip.c if the package
is compiled with Address Sanitizer. Remote attackers could leverage this
vulnerability to cause a denial of service via a crafted zip file
(CVE-2018-6869).

An out of bounds read was found in function zzip_disk_fread of ZZIPlib, up to
0.13.68, when ZZIPlib mem_disk functionality is used. Remote attackers could
leverage this vulnerability to cause a denial of service via a crafted zip
file (CVE-2018-7725).

An improper input validation was found in function __zzip_fetch_disk_trailer
of ZZIPlib, up to 0.13.68, that could lead to a crash in
__zzip_parse_root_directory function of zzip/zip.c. Remote attackers could
leverage this vulnerability to cause a denial of service via a crafted zip
file (CVE-2018-7726).

A memory leak was found in unzip-mem.c and unzzip-mem.c of ZZIPlib, up to
v0.13.68, that could lead to resource exhaustion. Local attackers could
leverage this vulnerability to cause a denial of service via a crafted zip
file (CVE-2018-7727).

An issue was discovered in ZZIPlib through 0.13.69. There is a memory leak
triggered in the function __zzip_parse_root_directory in zip.c, which could
lead to a denial of service attack (CVE-2018-16548).

A flaw was found in ZZIPlib 0.13.69. A directory traversal vulnerability
allows attackers to overwrite arbitrary files via a .. (dot dot) in a zip
file, because of the function unzzip_cat in the bins/unzzipcat-mem.c file
(CVE-2018-17828).");

  script_tag(name:"affected", value:"'zziplib' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64zziplib-0_13", rpm:"lib64zziplib-0_13~0.13.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zziplib-devel", rpm:"lib64zziplib-devel~0.13.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzziplib-0_13", rpm:"libzziplib-0_13~0.13.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzziplib-devel", rpm:"libzziplib-devel~0.13.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zziplib", rpm:"zziplib~0.13.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zziplib-utils", rpm:"zziplib-utils~0.13.69~1.mga6", rls:"MAGEIA6"))) {
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
