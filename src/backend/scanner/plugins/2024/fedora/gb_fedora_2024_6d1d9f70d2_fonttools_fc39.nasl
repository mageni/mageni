# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885612");
  script_version("2024-02-02T14:37:52+0000");
  script_cve_id("CVE-2023-45139");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 16:15:46 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-25 02:01:57 +0000 (Thu, 25 Jan 2024)");
  script_name("Fedora: Security Advisory for fonttools (FEDORA-2024-6d1d9f70d2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6d1d9f70d2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VY63B4SGY4QOQGUXMECRGD6K3YT3GJ75");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fonttools'
  package(s) announced via the FEDORA-2024-6d1d9f70d2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fontTools is a library for manipulating fonts, written in Python. The project
includes the TTX tool, that can convert TrueType and OpenType fonts to and
from an XML text format, which is also called TTX. It supports TrueType,
OpenType, AFM and to an extent Type 1 and some Mac-specific formats.");

  script_tag(name:"affected", value:"'fonttools' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"fonttools", rpm:"fonttools~4.43.1~1.fc39", rls:"FC39"))) {
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