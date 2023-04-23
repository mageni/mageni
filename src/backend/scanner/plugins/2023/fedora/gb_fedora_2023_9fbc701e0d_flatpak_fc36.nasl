# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827432");
  script_version("2023-04-07T10:09:45+0000");
  script_cve_id("CVE-2023-28100", "CVE-2023-28101");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-07 10:09:45 +0000 (Fri, 07 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 01:06:41 +0000 (Mon, 03 Apr 2023)");
  script_name("Fedora: Security Advisory for flatpak (FEDORA-2023-9fbc701e0d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9fbc701e0d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/63QA74TANHDH3JAHBAQ3VDSSOVX42NXA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak'
  package(s) announced via the FEDORA-2023-9fbc701e0d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"flatpak is a system for building, distributing and running sandboxed desktop
applications on Linux.");

  script_tag(name:"affected", value:"'flatpak' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.12.8~1.fc36", rls:"FC36"))) {
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
