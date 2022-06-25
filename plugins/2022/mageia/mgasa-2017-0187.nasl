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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0187");
  script_cve_id("CVE-2017-1000363", "CVE-2017-1000364", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-7487", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:25:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0187");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0187.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21149");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21043");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20886");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20803");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-216.html");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.69");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.70");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.71");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.72");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.73");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.74");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream 4.4.74 and fixes at least
the following security issues:

The ipxitf_ioctl function in net/ipx/af_ipx.c in the Linux kernel through
4.11.1 mishandles reference counts, which allows local users to cause a
denial of service (use-after-free) or possibly have unspecified other
impact via a failed SIOCGIFADDR ioctl call for an IPX interface
(CVE-2017-7487).

The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the
Linux kernel through 4.10.15 allows attackers to cause a denial of service
(double free) or possibly have unspecified other impact by leveraging use
of the accept system call (CVE-2017-8890).

The IPv6 fragmentation implementation in the Linux kernel through 4.11.1
does not consider that the nexthdr field may be associated with an invalid
option, which allows local users to cause a denial of service (out-of-bounds
read and BUG) or possibly have unspecified other impact via crafted socket
and send system calls (CVE-2017-9074).

The sctp_v6_create_accept_sk function in net/sctp/ipv6.c in the Linux kernel
through 4.11.1 mishandles inheritance, which allows local users to cause a
denial of service or possibly have unspecified other impact via crafted
system calls, a related issue to CVE-2017-8890 (CVE-2017-9075).

The dccp_v6_request_recv_sock function in net/dccp/ipv6.c in the Linux kernel
through 4.11.1 mishandles inheritance, which allows local users to cause a
denial of service or possibly have unspecified other impact via crafted
system calls, a related issue to CVE-2017-8890 (CVE-2017-9076).

The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel
through 4.11.1 mishandles inheritance, which allows local users to cause a
denial of service or possibly have unspecified other impact via crafted
system calls, a related issue to CVE-2017-8890 (CVE-2017-9077).

The __ip6_append_data function in net/ipv6/ip6_output.c in the Linux kernel
through 4.11.3 is too late in checking whether an overwrite of an skb data
structure may occur, which allows local users to cause a denial of service
(system crash) via crafted system calls (CVE-2017-9242).

The vmw_gb_surface_define_ioctl function (accessible via
DRM_IOCTL_VMW_GB_SURFACE_CREATE) in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c
in the Linux kernel through 4.11.4 defines a backup_handle variable but
does not give it an initial value. If one attempts to create a GB surface,
with a previously allocated DMA buffer to be used as a backup buffer, the
backup_handle variable does not get written to and is then later returned
to user space, allowing local users to obtain sensitive information from
uninitialized kernel memory via a crafted ioctl call (CVE-2017-9605).

A vulnerability was found in the Linux kernel's lp_setup() function where it
doesn't apply any bounds checking when passing 'lp=none'. This can result
into overflow of the parport_nr[] array. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.74~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.74-1.mga5", rpm:"kernel-tmb-desktop-4.4.74-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.74-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.74-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.74~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.74~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.74-1.mga5", rpm:"kernel-tmb-source-4.4.74-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.74~1.mga5", rls:"MAGEIA5"))) {
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
