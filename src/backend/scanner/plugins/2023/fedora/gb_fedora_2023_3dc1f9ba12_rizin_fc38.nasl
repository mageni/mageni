# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827920");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2023-27590");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-13 01:08:07 +0000 (Thu, 13 Jul 2023)");
  script_name("Fedora: Security Advisory for rizin (FEDORA-2023-3dc1f9ba12)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-3dc1f9ba12");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WW3JXI4TIJIR7PGFP74SN7GQYHW2F46Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rizin'
  package(s) announced via the FEDORA-2023-3dc1f9ba12 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rizin is a free and open-source Reverse Engineering framework, providing a
complete binary analysis experience with features like Disassembler,
Hexadecimal editor, Emulation, Binary inspection, Debugger, and more.

Rizin is a fork of radare2 with a focus on usability, working features and code
cleanliness.");

  script_tag(name:"affected", value:"'rizin' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"rizin", rpm:"rizin~0.5.2~1.fc38.2", rls:"FC38"))) {
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