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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0055");
  script_cve_id("CVE-2013-4579", "CVE-2014-0038", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1690");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-03 02:29:00 +0000 (Wed, 03 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0055)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0055");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0055.html");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.27");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.28");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12521");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-vserver' package(s) announced via the MGASA-2014-0055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update provides an update to the 3.10 longterm branch,
currently 3.10.28 and fixes the following security issues:

The ath9k_htc_set_bssid_mask function in
drivers/net/wireless/ath/ath9k/htc_drv_main.c in the Linux kernel through
3.12 uses a BSSID masking approach to determine the set of MAC addresses
on which a Wi-Fi device is listening, which allows remote attackers to
discover the original MAC address after spoofing by sending a series of
packets to MAC addresses with certain bit manipulations. (CVE-2013-4579)

Pageexec reported a bug in the Linux kernel's recvmmsg syscall when called
from code using the x32 ABI. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or gain administrator
privileges (CVE-2014-0038)

Faults during task-switch due to unhandled FPU-exceptions allow to
kill processes at random on all affected kernels, resulting in local
DOS in the end. One some architectures, privilege escalation under
non-common circumstances is possible. (CVE-2014-1438)

The hamradio yam_ioctl() code fails to initialise the cmd field of the
struct yamdrv_ioctl_cfg leading to a 4-byte info leak. (CVE-2014-1446)

Linux kernel built with the NetFilter Connection Tracking(NF_CONNTRACK)
support for IRC protocol(NF_NAT_IRC), is vulnerable to an information
leakage flaw. It could occur when communicating over direct
client-to-client IRC connection(/dcc) via a NAT-ed network. Kernel
attempts to mangle IRC TCP packet's content, wherein an uninitialised
'buffer' object is copied to a socket buffer and sent over to the other
end of a connection. (CVE-2014-1690)

For other changes, see the referenced changelogs:");

  script_tag(name:"affected", value:"'kernel-vserver' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-3.10.28-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-3.10.28-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver", rpm:"kernel-vserver~3.10.28~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-3.10.28-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-devel-3.10.28-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-latest", rpm:"kernel-vserver-devel-latest~3.10.28~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-doc", rpm:"kernel-vserver-doc~3.10.28~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-latest", rpm:"kernel-vserver-latest~3.10.28~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-3.10.28-0.vs2.3.6.8.1.mga3", rpm:"kernel-vserver-source-3.10.28-0.vs2.3.6.8.1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-latest", rpm:"kernel-vserver-source-latest~3.10.28~0.vs2.3.6.8.1.mga3", rls:"MAGEIA3"))) {
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
