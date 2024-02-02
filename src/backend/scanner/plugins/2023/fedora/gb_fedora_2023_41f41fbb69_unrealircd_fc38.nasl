# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885496");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-50784");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 16:09:00 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-26 02:25:52 +0000 (Tue, 26 Dec 2023)");
  script_name("Fedora: Security Advisory for unrealircd (FEDORA-2023-41f41fbb69)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-41f41fbb69");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BV6TFYPQOKYRGPEAKOWSO6PSCBV6LUR3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrealircd'
  package(s) announced via the FEDORA-2023-41f41fbb69 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"UnrealIRCd is an Open Source IRC server based on the branch of IRCu called
Dreamforge, formerly used by the DALnet IRC network. Since the beginning of
development on UnrealIRCd in May of 1999, it has become a highly advanced
IRCd with a strong focus on modularity, an advanced and highly configurable
configuration file. Key features include SSL/TLS, cloaking, advanced anti-
flood and anti-spam systems, swear filtering and module support.");

  script_tag(name:"affected", value:"'unrealircd' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"unrealircd", rpm:"unrealircd~6.1.4~1.fc38", rls:"FC38"))) {
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