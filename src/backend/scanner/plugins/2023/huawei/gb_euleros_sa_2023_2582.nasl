# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2582");
  script_cve_id("CVE-2023-24593", "CVE-2023-25180", "CVE-2023-29499", "CVE-2023-32611", "CVE-2023-32636", "CVE-2023-32643", "CVE-2023-32665");
  script_tag(name:"creation_date", value:"2023-08-08 04:15:41 +0000 (Tue, 08 Aug 2023)");
  script_version("2023-09-25T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-25 05:05:21 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 14:32:00 +0000 (Wed, 20 Sep 2023)");

  script_name("Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2023-2582)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2582");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2582");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2023-2582 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GLib incorrectly handled non-normal GVariants. An attacker could use this issue to cause GLib to crash, resulting in a denial of service, or perform other unknown attacks. Update Instructions: Run `sudo pro fix USN-6165-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions: libglib2.0-0 - 2.64.6-1~ubuntu20.04.6 libglib2.0-data - 2.64.6-1~ubuntu20.04.6 libglib2.0-tests - 2.64.6-1~ubuntu20.04.6 libglib2.0-doc - 2.64.6-1~ubuntu20.04.6 libglib2.0-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev - 2.64.6-1~ubuntu20.04.6 No subscription required(CVE-2023-32665)

It was discovered that GLib incorrectly handled non-normal GVariants. An attacker could use this issue to cause GLib to crash, resulting in a denial of service, or perform other unknown attacks. Update Instructions: Run `sudo pro fix USN-6165-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions: libglib2.0-0 - 2.64.6-1~ubuntu20.04.6 libglib2.0-data - 2.64.6-1~ubuntu20.04.6 libglib2.0-tests - 2.64.6-1~ubuntu20.04.6 libglib2.0-doc - 2.64.6-1~ubuntu20.04.6 libglib2.0-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev - 2.64.6-1~ubuntu20.04.6 No subscription required(CVE-2023-29499)

It was discovered that GLib incorrectly handled non-normal GVariants. An attacker could use this issue to cause GLib to crash, resulting in a denial of service, or perform other unknown attacks. Update Instructions: Run `sudo pro fix USN-6165-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions: libglib2.0-0 - 2.64.6-1~ubuntu20.04.6 libglib2.0-data - 2.64.6-1~ubuntu20.04.6 libglib2.0-tests - 2.64.6-1~ubuntu20.04.6 libglib2.0-doc - 2.64.6-1~ubuntu20.04.6 libglib2.0-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev - 2.64.6-1~ubuntu20.04.6 No subscription required(CVE-2023-32643)

It was discovered that GLib incorrectly handled non-normal GVariants. An attacker could use this issue to cause GLib to crash, resulting in a denial of service, or perform other unknown attacks. Update Instructions: Run `sudo pro fix USN-6165-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions: libglib2.0-0 - 2.64.6-1~ubuntu20.04.6 libglib2.0-data - 2.64.6-1~ubuntu20.04.6 libglib2.0-tests - 2.64.6-1~ubuntu20.04.6 libglib2.0-doc - 2.64.6-1~ubuntu20.04.6 libglib2.0-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev-bin - 2.64.6-1~ubuntu20.04.6 libglib2.0-dev - 2.64.6-1~ubuntu20.04.6 No subscription required(CVE-2023-32636)

It was discovered that GLib incorrectly handled non-normal GVariants. An attacker could use this issue to cause GLib to crash, resulting in a denial of service, or perform ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'glib2' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

  if(!isnull(res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.62.5~3.h13.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
