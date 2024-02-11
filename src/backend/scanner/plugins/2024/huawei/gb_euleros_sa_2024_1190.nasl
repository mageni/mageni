# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1190");
  script_cve_id("CVE-2023-0494", "CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"creation_date", value:"2024-02-09 04:23:45 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 07:15:30 +0000 (Wed, 13 Dec 2023)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2024-1190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1190");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1190");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2024-1190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in X.Org. This issue occurs due to a dangling pointer in DeepCopyPointerClasses that can be exploited by ProcXkbSetDeviceInfo() and ProcXkbGetDeviceInfo() to read and write into freed memory. This can lead to local privilege elevation on systems where the X server runs privileged and remote code execution for ssh X forwarding sessions.(CVE-2023-0494)

A flaw was found in xorg-server. Querying or changing XKB button actions such as moving from a touchpad to a mouse can result in out-of-bounds memory reads and writes. This may allow local privilege escalation or possible remote code execution in cases where X11 forwarding is involved.(CVE-2023-6377)

A flaw was found in xorg-server. A specially crafted request to RRChangeProviderProperty or RRChangeOutputProperty can trigger an integer overflow which may lead to a disclosure of sensitive information.(CVE-2023-6478)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-help", rpm:"xorg-x11-server-help~1.20.6~5.h10.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
