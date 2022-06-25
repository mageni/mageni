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
  script_oid("1.3.6.1.4.1.25623.1.0.884189");
  script_version("2022-01-20T06:32:54+0000");
  script_cve_id("CVE-2020-25704", "CVE-2020-36322", "CVE-2021-42739");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-01-20 06:32:54 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 02:00:42 +0000 (Wed, 19 Jan 2022)");
  script_name("CentOS: Security Advisory for kernel (CESA-2022:0063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:0063");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-January/073546.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2022:0063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: perf_event_parse_addr_filter memory (CVE-2020-25704)

  * kernel: fuse: fuse_do_getattr() calls make_bad_inode() in inappropriate
situations (CVE-2020-36322)

  * kernel: Heap buffer overflow in firedtv driver (CVE-2021-42739)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * A gfs2 withdrawal occurs function = gfs2_setbit, file = fs/gfs2/rgrp.c,
line = 109 (BZ#1364234)

  * i40e SR-IOV TX driver issue detected on VF 7 - VF connectivity loose
after VF down/up (BZ#1977246)

  * duplicate ACK not sent when expected (BZ#1990665)

  * [kernel-debug] BUG: bad unlock balance detected! when running LTP
read_all (BZ#2006536)

  * Rudimentary support for AMD Milan - Call init_amd_zn() om Family 19h
processors (BZ#2019218)

  * A VM with <=8 CPUs handles all the Mellanox NIC interrupts on CPU0 only,
causing low performance (BZ#2019272)

  * fix _PSD override quirk for AMD family 19h+ (BZ#2019588)

  * generic_file_aio_read returns 0 when interrupted early with a fatal
signal (BZ#2020857)");

  script_tag(name:"affected", value:"'kernel' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.53.1.el7", rls:"CentOS7"))) {
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