# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885189");
  script_version("2023-12-06T05:06:11+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:42 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for netconsd (FEDORA-2023-c981dcad74)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c981dcad74");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3YQRA5UKDH77CZEW5U54WTM6XVMTXNWY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netconsd'
  package(s) announced via the FEDORA-2023-c981dcad74 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a daemon for receiving and processing logs from the Linux Kernel, as
emitted over a network by the kernel&#39, s netconsole module. It supports both the
old 'legacy' text-only format, and the new extended format added in v4.4.

The core of the daemon does nothing but process messages and drop them: in order
to make the daemon useful, the user must supply one or more 'output modules'.
These modules are shared object files which expose a small ABI that is called by
netconsd with the content and metadata for netconsole messages it receives.");

  script_tag(name:"affected", value:"'netconsd' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"netconsd", rpm:"netconsd~0.4~1.fc39", rls:"FC39"))) {
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