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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0117");
  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0117)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0117");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0117.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22482");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-01/msg00106.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/L2ULSX6GBGUOCP4V67LMFVR2C7DKKXCU/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the MGASA-2018-0117 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to a lack of input validation checking mechanisms
during certain mail parsing operations (mbox.c operations on bounce
messages). If successfully exploited, the ClamAV software could allow a
variable pointing to the mail body which could cause a used after being
free (use-after-free) instance which may lead to a disruption of services
on an affected device to include a denial of service condition.
(CVE-2017-12374)

The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to a lack of input validation checking mechanisms
during certain mail parsing functions (the rfc2047 function in mbox.c). An
unauthenticated, remote attacker could exploit this vulnerability by
sending a crafted email to the affected device. This action could cause a
buffer overflow condition when ClamAV scans the malicious email, allowing
the attacker to potentially cause a DoS condition on an affected device.
(CVE-2017-12375)

ClamAV AntiVirus software versions 0.99.2 and prior contain a vulnerability
that could allow an unauthenticated, remote attacker to cause a denial of
service (DoS) condition or potentially execute arbitrary code on an affected
device. The vulnerability is due to improper input validation checking
mechanisms when handling Portable Document Format (.pdf) files sent to an
affected device. An unauthenticated, remote attacker could exploit this
vulnerability by sending a crafted .pdf file to an affected device. This
action could cause a handle_pdfname (in pdf.c) buffer overflow when ClamAV
scans the malicious file, allowing the attacker to cause a DoS condition
or potentially execute arbitrary code. (CVE-2017-12376)

ClamAV AntiVirus software versions 0.99.2 and prior contain a vulnerability
that could allow an unauthenticated, remote attacker to cause a denial of
service (DoS) condition or potentially execute arbitrary code on an affected
device. The vulnerability is due to improper input validation checking
mechanisms in mew packet files sent to an affected device. A successful
exploit could cause a heap-based buffer over-read condition in mew.c when
ClamAV scans the malicious file, allowing the attacker to cause a DoS
condition or potentially execute arbitrary code on the affected device.
(CVE-2017-12377)

ClamAV AntiVirus software versions 0.99.2 and prior contain a vulnerability
that could allow an unauthenticated, remote attacker to cause a denial of
service (DoS) condition on an affected device. The vulnerability is due to
improper input validation checking mechanisms of .tar (Tape Archive) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'clamav' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav7", rpm:"lib64clamav7~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.99.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7", rpm:"libclamav7~0.99.3~1.mga6", rls:"MAGEIA6"))) {
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
