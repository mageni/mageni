# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2325");
  script_cve_id("CVE-2022-4283", "CVE-2022-46340", "CVE-2022-46341", "CVE-2022-46342", "CVE-2022-46343", "CVE-2022-46344");
  script_tag(name:"creation_date", value:"2023-07-10 04:14:53 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 20:32:00 +0000 (Mon, 19 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2023-2325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2325");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2325");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2023-2325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in X.Org. This security flaw occurs because the XkbCopyNames function left a dangling pointer to freed memory, resulting in out-of-bounds memory access on subsequent XkbGetKbdByName requests.. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-4283)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XvdiSelectVideoNotify request may write to memory after it has been freed. This issue can lead to local privileges elevation on systems where the X se(CVE-2022-46342)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIChangeProperty request has a length-validation issues, resulting in out-of-bounds memory reads and potential information disclosure. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46344)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIPassiveUngrab request accesses out-of-bounds memory when invoked with a high keycode or button code. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46341)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the ScreenSaverSetAttributes request may write to memory after it has been freed. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46343)

A vulnerability was found in X.Org. This security flaw occurs becuase the swap handler for the XTestFakeInput request of the XTest extension may corrupt the stack if GenericEvents with lengths larger than 32 bytes are sent through a the XTestFakeInput request. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions. This issue does not affect systems where client and server use the same byte order.(CVE-2022-46340)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-help", rpm:"xorg-x11-server-help~1.20.6~5.h9.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
