# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2561");
  script_cve_id("CVE-2023-1667", "CVE-2023-2283");
  script_tag(name:"creation_date", value:"2023-08-03 04:14:57 +0000 (Thu, 03 Aug 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-06 14:54:00 +0000 (Tue, 06 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for libssh (EulerOS-SA-2023-2561)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2561");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2561");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libssh' package(s) announced via the EulerOS-SA-2023-2561 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in libssh, where the authentication check of the connecting client can be bypassed in the`pki_verify_data_signature` function in memory allocation problems. This issue may happen if there is insufficient memory or the memory usage is limited. The problem is caused by the return value `rc,` which is initialized to SSH_ERROR and later rewritten to save the return value of the function call `pki_key_check_hash_compatible.` The value of the variable is not changed between this point and the cryptographic verification. Therefore any error between them calls `goto error` returning SSH_OK.(CVE-2023-2283)

A NULL pointer dereference was found In libssh during re-keying with algorithm guessing. This issue may allow an authenticated client to cause a denial of service.(CVE-2023-1667)");

  script_tag(name:"affected", value:"'libssh' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.9.4~3.h12.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
