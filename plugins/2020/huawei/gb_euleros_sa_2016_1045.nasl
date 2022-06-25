# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1045");
  script_version("2020-01-23T10:40:13+0000");
  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 10:40:13 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:40:13 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libarchive (EulerOS-SA-2016-1045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1045");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libarchive' package(s) announced via the EulerOS-SA-2016-1045 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way libarchive handled hardlink archive entries of non-zero size. Combined with flaws in libarchive's file system sandboxing, this issue could cause an application using libarchive to overwrite arbitrary files with arbitrary data from the archive. (CVE-2016-5418)

Multiple out-of-bounds write flaws were found in libarchive.
Specially crafted ZIP, 7ZIP, or RAR files could cause a heap overflow, potentially allowing code execution in the context of the application using libarchive. (CVE-2016-1541, CVE-2016-4300, CVE-2016-4302)

Multiple out-of-bounds read flaws were found in libarchive.
Specially crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR files could cause the application to read data out of bounds, potentially disclosing a small amount of application memory, or causing an application crash. (CVE-2015-8919, CVE-2015-8920, CVE-2015-8921, CVE-2015-8923, CVE-2015-8924, CVE-2015-8925, CVE-2015-8926, CVE-2015-8928, CVE-2015-8934)

Multiple NULL pointer dereference flaws were found in libarchive.
Specially crafted RAR, CAB, or 7ZIP files could cause an application using libarchive to crash. (CVE-2015-8916, CVE-2015-8917, CVE-2015-8922)

Multiple infinite loop / resource exhaustion flaws were found in libarchive. Specially crafted GZIP or ISO files could cause the application to consume an excessive amount of resources, eventually leading to a crash on memory exhaustion. (CVE-2016-7166, CVE-2015-8930)

A denial of service vulnerability was found in libarchive. A specially crafted CPIO archive containing a symbolic link to a large target path could cause memory allocation to fail, causing an application using libarchive that attempted to view or extract such archive to crash. (CVE-2016-4809)

An integer overflow flaw, leading to a buffer overflow, was found in libarchive's construction of ISO9660 volumes. Attempting to create an ISO9660 volume with 2 GB or 4 GB file names could cause the application to attempt to allocate 20 GB of memory. If this were to succeed, it could lead to an out of bounds write on the heap and potential code execution. (CVE-2016-6250)

Multiple instances of undefined behavior due to arithmetic overflow were found in libarchive. Specially crafted MTREE archives, Compress streams, or ISO9660 volumes could potentially cause the application to fail to read the archive, or to crash. (CVE-2015-8931, CVE-2015-8932, CVE-2016-5844)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.1.2~10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);