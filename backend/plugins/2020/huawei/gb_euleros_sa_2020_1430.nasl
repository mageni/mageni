# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1430");
  script_version("2020-04-16T05:51:43+0000");
  script_cve_id("CVE-2013-4544", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-5745", "CVE-2015-6815", "CVE-2015-6855", "CVE-2015-7295", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2016-1568", "CVE-2016-2198", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2858", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4037", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7161", "CVE-2016-7421", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8576", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2016-9381", "CVE-2016-9907", "CVE-2016-9911", "CVE-2017-10806", "CVE-2017-11434", "CVE-2017-18043", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-8309", "CVE-2017-9373", "CVE-2017-9374", "CVE-2018-10839", "CVE-2018-15746", "CVE-2018-17958", "CVE-2018-17963", "CVE-2019-11135", "CVE-2019-14378", "CVE-2019-6778", "CVE-2020-7039", "CVE-2020-8608");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 05:51:43 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-1430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1430");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'qemu-kvm' package(s) announced via the EulerOS-SA-2020-1430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer overflow in later code.(CVE-2020-8608)



This vulnerability has been modified since it was last analyzed by the NVD. It is awaiting reanalysis which may result in further changes to the information provided.(CVE-2019-11135)



tcp_emu in tcp_subr.c in libslirp 4.1.0, as used in QEMU 4.2.0, mismanages memory, as demonstrated by IRC DCC commands in EMU_IRC. This can cause a heap-based buffer overflow or other out-of-bounds access which can lead to a DoS or potential execute arbitrary code.(CVE-2020-7039)



ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer overflow via a large packet because it mishandles a case involving the first fragment.(CVE-2019-14378)



Integer overflow in the VNC display driver in QEMU before 2.1.0 allows attachers to cause a denial of service (process crash) via a CLIENT_CUT_TEXT message, which triggers an infinite loop.(CVE-2015-5239)



Buffer overflow in the send_control_msg function in hw/char/virtio-serial-bus.c in QEMU before 2.4.0 allows guest users to cause a denial of service (QEMU process crash) via a crafted virtio control message.(CVE-2015-5745)



The ne2000_receive function in hw/net/ne2000.c in QEMU before 2.4.0.1 allows attackers to cause a denial of service (infinite loop and instance crash) or possibly execute arbitrary code via vectors related to receiving packets.(CVE-2015-5278)



The process_tx_desc function in hw/net/e1000.c in QEMU before 2.4.0.1 does not properly process transmit descriptor data when sending a network packet, which allows attackers to cause a denial of service (infinite loop and guest crash) via unspecified vectors.(CVE-2015-6815)



Heap-based buffer overflow in the ne2000_receive function in hw/net/ne2000.c in QEMU before 2.4.0.1 allows guest OS users to cause a denial of service (instance crash) or possibly execute arbitrary code via vectors related to receiving packets.(CVE-2015-5279)



Heap-based buffer overflow in the .receive callback of xlnx.xps-ethernetlite in QEMU (aka Quick Emulator) allows attackers to execute arbitrary code on the QEMU host via a large ethlite packet.(CVE-2016-7161)



hw/net/vmxnet3.c in QEMU 2.0.0-rc0, 1.7.1, and earlier allows local guest users to cause a denial of service or possibly execute arbitrary code via vectors related to (1) RX or (2) TX queue numbers or (3) interrupt indices. NOTE: some of these details are obtained from third party information.(CVE-2013-4544)



The slirp_smb function in net/slirp.c in QEMU 2.3.0 and earlier creates temporary files with predict ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~156.5.h12", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~156.5.h12", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~156.5.h12", rls:"EULEROS-2.0SP3"))) {
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