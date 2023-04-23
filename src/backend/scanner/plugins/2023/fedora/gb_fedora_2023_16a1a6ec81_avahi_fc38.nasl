# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827527");
  script_version("2023-04-20T10:42:24+0000");
  script_cve_id("CVE-2023-1981");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-20 10:42:24 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 01:06:10 +0000 (Wed, 19 Apr 2023)");
  script_name("Fedora: Security Advisory for avahi (FEDORA-2023-16a1a6ec81)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-16a1a6ec81");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VCTAFULPERZVYFFVHM7IEYXYRNHQDJAU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi'
  package(s) announced via the FEDORA-2023-16a1a6ec81 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Avahi is a system which facilitates service discovery on
a local network -- this means that you can plug your laptop or
computer into a network and instantly be able to view other people who
you can chat with, find printers to print to or find files being
shared. This kind of technology is already found in MacOS X (branded
&#39, Rendezvous&#39, , &#39, Bonjour&#39, and sometimes &#39, ZeroConf&#39, ) and is very
convenient.");

  script_tag(name:"affected", value:"'avahi' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.8~22.fc38", rls:"FC38"))) {
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