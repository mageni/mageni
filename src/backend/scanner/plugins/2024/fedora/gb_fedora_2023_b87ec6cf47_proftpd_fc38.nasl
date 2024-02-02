# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885521");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 03:15:00 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-30 02:16:35 +0000 (Sat, 30 Dec 2023)");
  script_name("Fedora: Security Advisory for proftpd (FEDORA-2023-b87ec6cf47)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b87ec6cf47");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QI3EHAHABFQK7OABNCSF5GMYP6TONTI7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd'
  package(s) announced via the FEDORA-2023-b87ec6cf47 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration. It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple &#39, virtual&#39, FTP servers, anonymous FTP, and permission-based directory
visibility.

This package defaults to the standalone behavior of ProFTPD, but all the
needed scripts to have it run by systemd instead are included.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.8b~1.fc38", rls:"FC38"))) {
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