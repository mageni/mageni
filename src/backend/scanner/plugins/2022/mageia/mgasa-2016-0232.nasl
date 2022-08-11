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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0232");
  script_cve_id("CVE-2013-4312", "CVE-2015-5257", "CVE-2015-5307", "CVE-2015-5327", "CVE-2015-6937", "CVE-2015-7550", "CVE-2015-7799", "CVE-2015-8104", "CVE-2015-8543", "CVE-2016-2085", "CVE-2016-2117", "CVE-2016-2143", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3713", "CVE-2016-3961");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0232");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0232.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18374");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_4.2");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_4.3");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_4.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.8");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.9");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.11");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.12");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.13");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2016-0232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update provides an upgrade to the upstream 4.4 longterm
kernel series, currently based on 4.4.13 and resolves at least the following
security issues:

The Linux kernel before 4.4.1 allows local users to bypass file-descriptor
limits and cause a denial of service (memory consumption) by sending each
descriptor over a UNIX socket before closing it, related to
net/unix/af_unix.c and net/unix/garbage.c (CVE-2013-4312).

drivers/usb/serial/whiteheat.c in the Linux kernel before 4.2.4 allows
physically proximate attackers to cause a denial of service (NULL pointer
dereference and OOPS) or possibly have unspecified other impact via a
crafted USB device (CVE-2015-5257).

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through
4.6.x, allows guest OS users to cause a denial of service (host OS panic or
hang) by triggering many #AC (aka Alignment Check) exceptions, related to
svm.c and vmx.c (CVE-2015-5307).

An out-of-bounds memory read was found, affecting kernels from 4.3-rc1
onwards. This vulnerability was caused by incorrect X.509 time validation
in x509_decode_time() function in x509_cert_parser.c (CVE-2015-5327).

The __rds_conn_create function in net/rds/connection.c in the Linux kernel
through 4.2.3 allows local users to cause a denial of service (NULL pointer
dereference and system crash) or possibly have unspecified other impact by
using a socket that was not properly bound (CVE-2015-6937).

The keyctl_read_key function in security/keys/keyctl.c in the Linux kernel
before 4.3.4 does not properly use a semaphore, which allows local users
to cause a denial of service (NULL pointer dereference and system crash)
or possibly have unspecified other impact via a crafted application that
leverages a race condition between keyctl_revoke and keyctl_read calls
(CVE-2015-7550).

The slhc_init function in drivers/net/slip/slhc.c in the Linux kernel
through 4.2.3 does not ensure that certain slot numbers are valid, which
allows local users to cause a denial of service (NULL pointer dereference
and system crash) via a crafted PPPIOCSMAXCID ioctl call (CVE-2015-7799).

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through
4.6.x, allows guest OS users to cause a denial of service (host OS panic
or hang) by triggering many #DB (aka Debug) exceptions, related to svm.c
(CVE-2015-8104).

The networking implementation in the Linux kernel through 4.3.3, as used
in Android and other products, does not validate protocol identifiers for
certain protocol families, which allows local users to cause a denial of
service (NULL function pointer dereference and system crash) or possibly
gain privileges by leveraging CLONE_NEWUSER support to execute a crafted
SOCK_RAW application (CVE-2015-8543).

The evm_verify_hmac function in security/integrity/evm/evm_main.c in the
Linux kernel before 4.5 does not properly copy data, which makes it easier
for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.4.13-1.mga5", rpm:"kernel-linus-4.4.13-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.4.13-1.mga5", rpm:"kernel-linus-devel-4.4.13-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.4.13-1.mga5", rpm:"kernel-linus-source-4.4.13-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.4.13~1.mga5", rls:"MAGEIA5"))) {
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
