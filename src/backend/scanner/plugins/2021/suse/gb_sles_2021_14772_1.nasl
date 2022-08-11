# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14772.1");
  script_cve_id("CVE-2020-11947", "CVE-2020-15469", "CVE-2020-15863", "CVE-2020-25707", "CVE-2021-20221", "CVE-2021-3416", "CVE-2021-3592", "CVE-2021-3594");
  script_tag(name:"creation_date", value:"2021-08-04 02:24:35 +0000 (Wed, 04 Aug 2021)");
  script_version("2021-08-04T02:24:35+0000");
  script_tag(name:"last_modification", value:"2021-08-05 10:56:26 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 05:15:00 +0000 (Thu, 08 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14772-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114772-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2021:14772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes the following issues:


CVE-2021-3594: invalid pointer initialization may lead to information
 disclosure in slirp (udp) (bsc#1187367)

CVE-2021-3592: invalid pointer initialization may lead to information
 disclosure (bootp). (bsc#1187364)

CVE-2021-3416: infinite loop in loopback mode may lead to stack
 overflow. (bsc#1186473)

CVE-2020-15469: MMIO ops null pointer dereference may lead to DoS.
 (bsc#1173612)

CVE-2020-11947: iscsi_aio_ioctl_cb in block/iscsi.c has a heap-based
 buffer over-read. (bsc#1180523)

CVE-2021-20221: out-of-bound heap buffer access via an interrupt ID
 field. (bsc#1181933)

CVE-2020-25707: infinite loop in e1000e_write_packet_to_guest() in
 hw/net/e1000e_core.c. (bsc#1178683)

CVE-2020-15863: stack-based overflow in xgmac_enet_send() in
 hw/net/xgmac.c. (bsc#1174386)");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~60.37.1", rls:"SLES11.0SP4"))) {
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
