# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827572");
  script_version("2023-04-27T12:17:38+0000");
  script_cve_id("CVE-2020-27827", "CVE-2021-43612");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 13:15:00 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2023-04-21 01:06:28 +0000 (Fri, 21 Apr 2023)");
  script_name("Fedora: Security Advisory for lldpd (FEDORA-2023-c0c184a019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c0c184a019");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3T5XHPOGIPWCRRPJUE6P3HVC5PTSD5JS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lldpd'
  package(s) announced via the FEDORA-2023-c0c184a019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LLDP is an industry standard protocol designed to supplant proprietary
Link-Layer protocols such as EDP or CDP. The goal of LLDP is to provide
an inter-vendor compatible mechanism to deliver Link-Layer notifications
to adjacent network devices.");

  script_tag(name:"affected", value:"'lldpd' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"lldpd", rpm:"lldpd~1.0.16~1.fc37", rls:"FC37"))) {
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