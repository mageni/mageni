# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827549");
  script_version("2023-04-27T12:17:38+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 01:06:28 +0000 (Fri, 21 Apr 2023)");
  script_name("Fedora: Security Advisory for parcellite (FEDORA-2023-e24d2cac37)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-e24d2cac37");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TVPMZCHBXJ7JLXD22ZOU4FXBPHM6MRB7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'parcellite'
  package(s) announced via the FEDORA-2023-e24d2cac37 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Parcellite is a stripped down, basic-features-only clipboard manager with a
small memory footprint for those who like simplicity.

In GNOME and Xfce the clipboard manager will be started automatically. For
other desktops or window managers you should also install a panel with a
system tray or notification area if you want to use this package.");

  script_tag(name:"affected", value:"'parcellite' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"parcellite", rpm:"parcellite~1.2.2~1.fc38", rls:"FC38"))) {
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