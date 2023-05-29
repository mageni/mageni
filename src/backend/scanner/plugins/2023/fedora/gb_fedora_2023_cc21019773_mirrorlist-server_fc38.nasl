# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827663");
  script_version("2023-05-09T09:12:26+0000");
  script_cve_id("CVE-2023-26964");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-09 09:12:26 +0000 (Tue, 09 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-08 01:06:55 +0000 (Mon, 08 May 2023)");
  script_name("Fedora: Security Advisory for mirrorlist-server (FEDORA-2023-cc21019773)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cc21019773");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QVH4SPRXEDOAC7HPQMNAXOY2GQACWCSY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mirrorlist-server'
  package(s) announced via the FEDORA-2023-cc21019773 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This implementation of the mirrorlist-server is written in Rust. The original
version of the mirrorlist-server was part of the MirrorManager2 repository and
it is implemented using Python. While moving from Python2 to Python3 one of
the problems was that the data exchange format (Python Pickle) did not support
running the MirrorManager2 backend with Python2 and the mirrorlist frontend
with Python3. To have a Pickle independent data exchange format protobuf was
introduced. The first try to use protobuf in the python mirrorlist
implementation required a lot more memory than the Pickle based implementation
(3.5GB instead of 1.1GB). That is one of the reasons a new mirrorlist-server
implementation was needed.

Another reason to rewrite the mirrorlist-server is its architecture. The
Python based version requires the Apache HTTP server or something that can
run the included wsgi. The wsgi talks over a socket to the actual
mirrorlist-server. In Fedora&#39, s MirrorManager2 instance this runs in a container
which runs behind HAProxy. This implementation in Rust directly uses a HTTP
library to reduce the number of involved components.

In addition to being simpler this implementation also requires less memory
than the Python version.");

  script_tag(name:"affected", value:"'mirrorlist-server' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server", rpm:"mirrorlist-server~3.0.6~6.fc38", rls:"FC38"))) {
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
