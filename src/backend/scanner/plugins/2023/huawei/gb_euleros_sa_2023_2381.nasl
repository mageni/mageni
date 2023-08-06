# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2381");
  script_cve_id("CVE-2023-24593", "CVE-2023-25180");
  script_tag(name:"creation_date", value:"2023-07-17 04:14:57 +0000 (Mon, 17 Jul 2023)");
  script_version("2023-07-17T05:05:06+0000");
  script_tag(name:"last_modification", value:"2023-07-17 05:05:06 +0000 (Mon, 17 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2023-2381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2381");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2381");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2023-2381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in GLib2.0, where denial of service caused by handling a malicious serialised variant which is structured to cause allocations or looping superlinear to its serialised size. Applications are at risk if they accept untrusted serialised variants by checking them with g_variant_get_normal_form() (or don't check them).(CVE-2023-25180)

A vulnerability was found in GLib2.0, where DoS caused by handling a malicious text-form variant which is structured to cause looping superlinear to its text size. Applications are at risk if they parse untrusted text-form variants.(CVE-2023-24593)");

  script_tag(name:"affected", value:"'glib2' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.62.5~6.h16.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
