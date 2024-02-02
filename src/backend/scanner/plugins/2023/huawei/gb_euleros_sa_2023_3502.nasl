# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3502");
  script_cve_id("CVE-2023-36054");
  script_tag(name:"creation_date", value:"2023-12-22 04:20:17 +0000 (Fri, 22 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 17:57:23 +0000 (Tue, 15 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for krb5 (EulerOS-SA-2023-3502)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3502");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3502");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'krb5' package(s) announced via the EulerOS-SA-2023-3502 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lib/kadm5/kadm_rpc_xdr.c in MIT Kerberos 5 (aka krb5) before 1.20.2 and 1.21.x before 1.21.1 frees an uninitialized pointer. A remote authenticated user can trigger a kadmind crash. This occurs because _xdr_kadm5_principal_ent_rec does not validate the relationship between n_key_data and the key_data array count.(CVE-2023-36054)");

  script_tag(name:"affected", value:"'krb5' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.18.2~2.h13.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.18.2~2.h13.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.18.2~2.h13.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.18.2~2.h13.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
