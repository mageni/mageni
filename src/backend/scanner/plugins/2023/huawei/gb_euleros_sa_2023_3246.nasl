# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3246");
  script_cve_id("CVE-2021-33634", "CVE-2021-33635", "CVE-2021-33636", "CVE-2021-33637", "CVE-2021-33638");
  script_tag(name:"creation_date", value:"2023-12-12 04:35:10 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 14:36:12 +0000 (Wed, 08 Nov 2023)");

  script_name("Huawei EulerOS: Security Advisory for iSulad (EulerOS-SA-2023-3246)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3246");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3246");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'iSulad' package(s) announced via the EulerOS-SA-2023-3246 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Isula uses the lxc runtime (default) to run malicious images, which can cause DOS.(CVE-2021-33634)

When malicious images are pulled by isula pull, attackers can execute arbitrary code.(CVE-2021-33635)

When the isula load command is used to load malicious images, attackers can execute arbitrary code.(CVE-2021-33636)

When the isula export command is used to export a container to an image and the container is controlled by an attacker, the attacker can escape the container.(CVE-2021-33637)

When the isula cp command is used to copy files from a container to a host machine and the container is controlled by an attacker, the attacker can escape the container.(CVE-2021-33638)");

  script_tag(name:"affected", value:"'iSulad' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"iSulad", rpm:"iSulad~2.0.11~6.h98.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
