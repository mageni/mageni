# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884990");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2023-22338", "CVE-2023-22840");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 18:46:00 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-10-12 01:15:48 +0000 (Thu, 12 Oct 2023)");
  script_name("Fedora: Security Advisory for oneVPL-intel-gpu (FEDORA-2023-b6aab4f954)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b6aab4f954");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2INF7VQONUCQPURRMMOSYYO77OC6ZRD7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oneVPL-intel-gpu'
  package(s) announced via the FEDORA-2023-b6aab4f954 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Intel oneVPL GPU Runtime is a Runtime implementation of oneVPL API for Intel Gen
GPUs. Runtime provides access to hardware-accelerated video decode, encode and
filtering.");

  script_tag(name:"affected", value:"'oneVPL-intel-gpu' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-intel-gpu", rpm:"oneVPL-intel-gpu~23.3.4~2.fc38", rls:"FC38"))) {
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