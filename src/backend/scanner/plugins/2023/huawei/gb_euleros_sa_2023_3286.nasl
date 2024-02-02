# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3286");
  script_cve_id("CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669");
  script_tag(name:"creation_date", value:"2023-12-12 04:35:10 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 18:20:56 +0000 (Tue, 14 Nov 2023)");

  script_name("Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2023-3286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3286");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3286");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2023-3286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in Samba, where the flaw allows SMB clients to truncate files, even with read-only permissions when the Samba VFS module 'acl_xattr' is configured with 'acl_xattr:ignore system acls = yes'. The SMB protocol allows opening files when the client requests read-only access but then implicitly truncates the opened file to 0 bytes if the client specifies a separate OVERWRITE create disposition request. The issue arises in configurations that bypass kernel file system permissions checks, relying solely on Samba's permissions.(CVE-2023-4091)

A design flaw was found in Samba's DirSync control implementation, which exposes passwords and secrets in Active Directory to privileged users and Read-Only Domain Controllers (RODCs). This flaw allows RODCs and users possessing the GET_CHANGES right to access all attributes, including sensitive secrets and passwords. Even in a default setup, RODC DC accounts, which should only replicate some passwords, can gain access to all domain secrets, including the vital krbtgt, effectively eliminating the RODC / DC distinction. Furthermore, the vulnerability fails to account for error conditions (fail open), like out-of-memory situations, potentially granting access to secret attributes, even under low-privileged attacker influence.(CVE-2023-4154)

A vulnerability was found in Samba's 'rpcecho' development server, a non-Windows RPC server used to test Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked indefinitely. The issue arises because the 'rpcecho' service operates with only one worker in the main RPC task, allowing calls to the 'rpcecho' server to be blocked for a specified time, causing service disruptions. This disruption is triggered by a 'sleep()' call in the 'dcesrv_echo_TestSleep()' function under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls to the 'rpcecho' server, requesting it to block for a specified duration, effectively disrupting most services and leading to a complete denial of service on the AD DC. The DoS affects all other services as 'rpcecho' runs in the main RPC task.(CVE-2023-42669)");

  script_tag(name:"affected", value:"'samba' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.15.3~4.h22.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
