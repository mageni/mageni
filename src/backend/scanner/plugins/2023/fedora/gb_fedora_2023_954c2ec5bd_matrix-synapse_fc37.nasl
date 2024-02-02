# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885060");
  script_version("2023-10-27T16:11:33+0000");
  script_cve_id("CVE-2023-45129");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 20:18:00 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 01:17:09 +0000 (Wed, 25 Oct 2023)");
  script_name("Fedora: Security Advisory for matrix-synapse (FEDORA-2023-954c2ec5bd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-954c2ec5bd");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KEVRB4MG5UXQ5RLZHSUJXM5GWEBYYS5B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse'
  package(s) announced via the FEDORA-2023-954c2ec5bd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matrix is an ambitious new ecosystem for open federated Instant Messaging and
VoIP. Synapse is a reference 'homeserver' implementation of Matrix from the
core development team. It is intended to showcase the concept of Matrix and
let folks see the spec in the context of a coded base and let you run your own
homeserver and generally help bootstrap the ecosystem.");

  script_tag(name:"affected", value:"'matrix-synapse' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~1.80.0~7.fc37", rls:"FC37"))) {
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
