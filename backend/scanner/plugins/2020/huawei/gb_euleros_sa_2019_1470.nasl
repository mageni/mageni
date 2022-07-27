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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1470");
  script_version("2020-01-23T11:48:26+0000");
  script_cve_id("CVE-2013-0211", "CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:48:26 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:48:26 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libarchive (EulerOS-SA-2019-1470)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1470");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libarchive' package(s) announced via the EulerOS-SA-2019-1470 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in libarchive. A specially crafted MTREE file could cause a small out-of-bounds read, potentially disclosing a small amount of application memory.(CVE-2015-8925)

A vulnerability was found in libarchive. An attempt to create an ISO9660 volume with 2GB or 4GB filenames could cause the application to crash.(CVE-2016-6250)

A vulnerability was found in libarchive. A specially crafted RAR file could cause the application to read memory beyond the end of the decompression buffer.(CVE-2015-8934)

A vulnerability was found in libarchive's handling of 7zip data. A specially crafted 7zip file can cause a integer overflow resulting in memory corruption that can lead to code execution.(CVE-2016-4300)

A vulnerability was found in libarchive. A specially crafted 7Z file could trigger a NULL pointer dereference, causing the application to crash.(CVE-2015-8922)

Undefined behavior (signed integer overflow) was discovered in libarchive, in the ISO parser. A crafted file could potentially cause denial of service.(CVE-2016-5844)

A vulnerability was found in libarchive. A specially crafted AR archive could cause the application to read a single byte of application memory, potentially disclosing it to the attacker.(CVE-2015-8920)

A vulnerability was found in libarchive. A specially crafted mtree file could cause libarchive to read beyond a statically declared structure, potentially disclosing application memory.(CVE-2015-8921)

A vulnerability was found in libarchive. A specially crafted LZA/LZH file could cause a small out-of-bounds read, potentially disclosing a few bytes of application memory.(CVE-2015-8919)

A vulnerability was found in libarchive. A specially crafted ISO file could cause the application to consume resources until it hit a memory limit, leading to a crash or denial of service.(CVE-2015-8930)

A vulnerability was found in libarchive. A specially crafted TAR file could trigger an out-of-bounds read, potentially causing the application to disclose a small amount of application memory.(CVE-2015-8924)

A vulnerability was found in libarchive. A specially crafted MTREE file could cause a limited out-of-bounds read, potentially disclosing contents of application memory.(CVE-2015-8928)

A vulnerability was found in libarchive. A specially crafted CAB file could cause the application dereference a NULL pointer, leading to a crash.(CVE-2015-8917)

A vulnerability was found in libarchive. A specially crafted RAR file could cause the application dereference a NULL pointer, leading to a crash.(CVE-2015-8916)

A vulnerability was found in libarchive's hand ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libarchive' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"ibarchive", rpm:"ibarchive~3.1.2~10.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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