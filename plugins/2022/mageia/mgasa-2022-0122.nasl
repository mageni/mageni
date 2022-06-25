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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0122");
  script_cve_id("CVE-2022-0995", "CVE-2022-1011", "CVE-2022-1015", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-26490", "CVE-2022-27666");
  script_tag(name:"creation_date", value:"2022-03-30 04:06:50 +0000 (Wed, 30 Mar 2022)");
  script_version("2022-03-30T04:06:50+0000");
  script_tag(name:"last_modification", value:"2022-03-30 10:16:33 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 14:34:00 +0000 (Thu, 24 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0122");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0122.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30200");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.29");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.30");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.31");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.32");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.32 and fixes at least
the following security issues:

An out-of-bounds (OOB) memory write flaw was found in the Linux kernel's
watch_queue event notification subsystem. This flaw can overwrite parts
of the kernel state, potentially allowing a local user to gain privileged
access or cause a denial of service on the system (CVE-2022-0995).

A flaw use after free in the Linux kernel FUSE filesystem was found in
the way user triggers write(). A local user could use this flaw to get
some unauthorized access to some data from the FUSE filesystem and as
result potentially privilege escalation too (CVE-2022-1011).

A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c
of the netfilter subsystem. This flaw allows a local user to cause an
out-of-bounds write issue (CVE-2022-1015).

A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:
nft_do_chain, which can cause a use-after-free. This issue needs to handle
'return' with proper preconditions, as it can lead to a kernel information
leak problem caused by a local, unprivileged attacker (CVE-2022-1016).

A use-after-free flaw was found in the Linux kernel's sound subsystem in
the way a user triggers concurrent calls of PCM hw_params. The hw_free
ioctls or similar race condition happens inside ALSA PCM for other ioctls.
This flaw allows a local user to crash or potentially escalate their
privileges on the system (CVE-2022-1048).

st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c has
EVT_TRANSACTION buffer overflows because of untrusted length parameters
(CVE-2022-26490).

There is a buffer overflow in ESP transformation in net/ipv4/esp4.c and
net/ipv6/esp6.c via a large message. In some configurations, local users
can gain privileges by overwriting kernel heap objects (CVE-2022-27666).

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.32-1.mga8", rpm:"kernel-linus-5.15.32-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.32~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.32-1.mga8", rpm:"kernel-linus-devel-5.15.32-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.32~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.32~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.32~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.32-1.mga8", rpm:"kernel-linus-source-5.15.32-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.32~1.mga8", rls:"MAGEIA8"))) {
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
