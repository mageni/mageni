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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0008");
  script_cve_id("CVE-2022-3424", "CVE-2022-3534", "CVE-2022-3545", "CVE-2022-36280", "CVE-2022-3643", "CVE-2022-41218", "CVE-2022-45934", "CVE-2022-47929", "CVE-2023-0210", "CVE-2023-0266", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0008)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0008");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0008.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31406");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.83");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.84");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.85");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.86");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.87");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.88");
  script_xref(name:"URL", value:"https://xenbits.xenproject.org/xsa/advisory-423.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0008 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.88 and fixes at least
the following security issues:

A use-after-free flaw was found in the Linux kernel's SGI GRU driver in
the way the first gru_file_unlocked_ioctl function is called by the user,
where a fail pass occurs in the gru_check_chiplet_assignment function.
This flaw allows a local user to crash or potentially escalate their
privileges on the system (CVE-2022-3424).

A vulnerability in the function btf_dump_name_dups of the file
tools/lib/bpf/ btf_dump.c of the component libbpf. This flaw allows a
manipulation that may lea to a use-after-free issue (CVE-2022-3534).

A vulnerability was found in area_cache_get in drivers/net/ethernet/
netronome/nfp/nfpcore/nfp_cppcore.c in the Netronome Flow Processor (NFP)
driver in the Linux kernel. This flaw allows a manipulation that may lead
to a use-after-free issue (CVE-2022-3545).

Guests can trigger NIC interface reset/abort/crash via netback. It is
possible for a guest to trigger a NIC interface reset/abort/crash in a
Linux based network backend by sending certain kinds of packets. It appears
to be an (unwritten?) assumption in the rest of the Linux network stack
that packet protocol headers are all contained within the linear section
of the SKB and some NICs behave badly if this is not the case. This has
been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780
(bnx2x) though it may be an issue with other NICs/drivers as well. In case
the frontend is sending requests with split headers, netback will forward
those violating above mentioned assumption to the networking core,
resulting in said misbehavior (CVE-2022-3643, XSA-423).

An out-of-bounds memory write vulnerability was found in the Linux kernel
vmwgfx driver in vmw_kms_cursor_snoop due to a missing check of a memcpy
length. This flaw allows a local, unprivileged attacker with access to
either the /dev/dri/card0 or /dev/dri/rendererD128 and able to issue an
ioctl() on the resulting file descriptor, to crash the system, causing
a denial of service (CVE-2022-36280).

A use-after-free flaw was found in the Linux kernel's dvb-core subsystem
(DVB API used by Digital TV devices) in how a user physically removed a
USB device (such as a DVB demultiplexer device) while running malicious
code. This flaw allows a local user to crash or potentially escalate their
privileges on the system (CVE-2022-41218).

An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req
in net/bluetooth/l2cap_core.c has an integer wraparound via L2CAP_CONF_REQ
packets (CVE-2022-45934).

In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the
traffic control subsystem allows an unprivileged user to trigger a denial
of service (system crash) via a crafted traffic control configuration that
is set up with 'tc qdisc' and 'tc class' commands. This affects qdisc_graft
in net/sched/sch_api.c ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.88-1.mga8", rpm:"kernel-linus-5.15.88-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.88~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.88-1.mga8", rpm:"kernel-linus-devel-5.15.88-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.88~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.88~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.88~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.88-1.mga8", rpm:"kernel-linus-source-5.15.88-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.88~1.mga8", rls:"MAGEIA8"))) {
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
