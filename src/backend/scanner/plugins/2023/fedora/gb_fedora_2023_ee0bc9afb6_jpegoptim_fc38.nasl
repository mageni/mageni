# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827458");
  script_version("2023-04-12T11:20:00+0000");
  script_cve_id("CVE-2023-27781");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-04 01:09:52 +0000 (Tue, 04 Apr 2023)");
  script_name("Fedora: Security Advisory for jpegoptim (FEDORA-2023-ee0bc9afb6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-ee0bc9afb6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/66ZW65INCWSQYIT5E6N6I6PE5D7R6EK7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jpegoptim'
  package(s) announced via the FEDORA-2023-ee0bc9afb6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jpegoptim is an utility to optimize JPEG files. Provides lossless optimization
(based on optimizing the Huffman tables) and 'lossy' optimization based on
setting maximum quality factor.");

  script_tag(name:"affected", value:"'jpegoptim' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"jpegoptim", rpm:"jpegoptim~1.5.3~1.fc38", rls:"FC38"))) {
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