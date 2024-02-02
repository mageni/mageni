# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885035");
  script_version("2023-10-27T16:11:33+0000");
  script_cve_id("CVE-2023-26112");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 13:57:00 +0000 (Mon, 10 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-10-20 01:19:39 +0000 (Fri, 20 Oct 2023)");
  script_name("Fedora: Security Advisory for python-configobj (FEDORA-2023-27b41bb133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-27b41bb133");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6BO4RLMYEJODCNUE3DJIIUUFVTPAG6VN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-configobj'
  package(s) announced via the FEDORA-2023-27b41bb133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ConfigObj is a simple but powerful configuration file reader and writer: an ini
file round tripper. Its main feature is that it is very easy to use, with a
straightforward programmers interface and a simple syntax for config files.");

  script_tag(name:"affected", value:"'python-configobj' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-configobj", rpm:"python-configobj~5.0.8~6.fc38", rls:"FC38"))) {
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