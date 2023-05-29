# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827711");
  script_version("2023-05-25T09:08:46+0000");
  script_cve_id("CVE-2023-26964");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-25 09:08:46 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-19 01:07:20 +0000 (Fri, 19 May 2023)");
  script_name("Fedora: Security Advisory for rust-ybaas (FEDORA-2023-37ae269843)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-37ae269843");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2F6UWCKOFYPUSBPKTCNOIZSTIZCBK3XK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-ybaas'
  package(s) announced via the FEDORA-2023-37ae269843 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Don&#39, t you love when you accidentally tap your Yubikey when you have your IRC
client in focus and you send 987947 into Libera? Want to be able to have that
experience without having to reach all the way over to your laptop&#39, s USB port?
Don&#39, t want the complexity of installing and using the yubibomb CLI tool? Now
you can use yubibomb as a service!");

  script_tag(name:"affected", value:"'rust-ybaas' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas", rpm:"rust-ybaas~0.0.10~7.fc37", rls:"FC37"))) {
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