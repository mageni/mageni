# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3460");
  script_cve_id("CVE-2015-8558", "CVE-2020-15469", "CVE-2020-15859", "CVE-2020-25742", "CVE-2020-25743", "CVE-2021-20203", "CVE-2022-26353", "CVE-2023-3180");
  script_tag(name:"creation_date", value:"2023-12-15 04:20:35 +0000 (Fri, 15 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-25 18:21:42 +0000 (Fri, 25 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2023-3460)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3460");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3460");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2023-3460 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ehci_process_itd function in hw/usb/hcd-ehci.c in QEMU allows local guest OS administrators to cause a denial of service (infinite loop and CPU consumption) via a circular isochronous transfer descriptor (iTD) list.(CVE-2015-8558)

In QEMU 4.2.0, a MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer dereference.(CVE-2020-15469)

An integer overflow issue was found in the vmxnet3 NIC emulator of the QEMU for versions up to v5.2.0. It may occur if a guest was to supply invalid values for rx/tx queue size or other NIC parameters. A privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-20203)

pci_change_irq_level in hw/pci/pci.c in QEMU before 5.1.1 has a NULL pointer dereference because pci_get_bus() might not return a valid pointer.(CVE-2020-25742)

hw/ide/pci.c in QEMU before 5.1.1 can trigger a NULL pointer dereference because it lacks a pointer check before an ide_cancel_dma_sync call.(CVE-2020-25743)

QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e packet with the data's address set to the e1000e's MMIO address.(CVE-2020-15859)

A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and other unexpected results. Affected QEMU version: 6.2.0.(CVE-2022-26353)

A flaw was found in the QEMU virtual crypto device while handling data encryption/decryption requests in virtio_crypto_handle_sym_req. There is no check for the value of `src_len` and `dst_len` in virtio_crypto_sym_op_helper, potentially leading to a heap buffer overflow when the two values differ.(CVE-2023-3180)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.515", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
