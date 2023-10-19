# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2906");
  script_cve_id("CVE-2022-1050", "CVE-2023-0664", "CVE-2023-2861", "CVE-2023-3180", "CVE-2023-3354");
  script_tag(name:"creation_date", value:"2023-10-09 09:58:45 +0000 (Mon, 09 Oct 2023)");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 12:26:00 +0000 (Fri, 08 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2023-2906)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2906");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2906");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2023-2906 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the QEMU built-in VNC server. When a client connects to the VNC server, QEMU checks whether the current number of connections crosses a certain threshold and if so, cleans up the previous connection. If the previous connection happens to be in the handshake phase and fails, QEMU cleans up the connection again, resulting in a NULL pointer dereference issue. This could allow a remote unauthenticated client to cause a denial of service.(CVE-2023-3354)

A flaw was found in the QEMU Guest Agent service for Windows. A local unprivileged user may be able to manipulate the QEMU Guest Agent's Windows installer via repair custom actions to elevate their privileges on the system.(CVE-2023-0664)

A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. This flaw allows a crafted guest driver to execute HW commands when shared buffers are not yet allocated, potentially leading to a use-after-free condition.(CVE-2022-1050)

A flaw was found in the 9p passthrough filesystem (9pfs) implementation in QEMU. The 9pfs server did not prohibit opening special files on the host side, potentially allowing a malicious client to escape from the exported 9p tree by creating and opening a device file in the shared folder.(CVE-2023-2861)

A flaw was found in the QEMU virtual crypto device while handling data encryption/decryption requests in virtio_crypto_handle_sym_req. There is no check for the value of `src_len` and `dst_len` in virtio_crypto_sym_op_helper, potentially leading to a heap buffer overflow when the two values differ.(CVE-2023-3180)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~4.1.0~16.h28.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
