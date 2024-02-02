# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3399");
  script_cve_id("CVE-2017-17840");
  script_tag(name:"creation_date", value:"2023-12-14 04:31:45 +0000 (Thu, 14 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-11 18:52:46 +0000 (Thu, 11 Jan 2018)");

  script_name("Huawei EulerOS: Security Advisory for iscsi-initiator-utils (EulerOS-SA-2023-3399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3399");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3399");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'iscsi-initiator-utils' package(s) announced via the EulerOS-SA-2023-3399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Open-iSCSI through 2.0.875. A local attacker can cause the iscsiuio server to abort or potentially execute code by sending messages with incorrect lengths, which (due to lack of checking) can lead to buffer overflows, and result in aborts (with overflow checking enabled) or code execution. The process_iscsid_broadcast function in iscsiuio/src/unix/iscsid_ipc.c does not validate the payload length before a write operation.(CVE-2017-17840)");

  script_tag(name:"affected", value:"'iscsi-initiator-utils' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"iscsi-initiator-utils", rpm:"iscsi-initiator-utils~6.2.0.874~8.h18.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsi-initiator-utils-iscsiuio", rpm:"iscsi-initiator-utils-iscsiuio~6.2.0.874~8.h18.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
