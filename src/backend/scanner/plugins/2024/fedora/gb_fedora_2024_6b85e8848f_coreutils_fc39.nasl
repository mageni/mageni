# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885602");
  script_version("2024-01-24T05:06:24+0000");
  script_cve_id("CVE-2024-0684");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-23 02:04:16 +0000 (Tue, 23 Jan 2024)");
  script_name("Fedora: Security Advisory for coreutils (FEDORA-2024-6b85e8848f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6b85e8848f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2KAURFJIEYY2BWCPN4AZDYCVMFD5J4GB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils'
  package(s) announced via the FEDORA-2024-6b85e8848f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"These are the GNU core utilities.  This package is the combination of
the old GNU fileutils, sh-utils, and textutils packages.");

  script_tag(name:"affected", value:"'coreutils' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~9.3~5.fc39", rls:"FC39"))) {
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