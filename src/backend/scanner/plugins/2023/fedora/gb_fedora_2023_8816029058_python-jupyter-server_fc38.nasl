# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885447");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-49080");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-07 20:32:00 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-14 02:19:56 +0000 (Thu, 14 Dec 2023)");
  script_name("Fedora: Security Advisory for python-jupyter-server (FEDORA-2023-8816029058)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8816029058");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FG2JWZI5KPUYMDPS53AIFTZJWZD3IT6I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-jupyter-server'
  package(s) announced via the FEDORA-2023-8816029058 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Jupyter Server provides the backend (i.e. the core services,
APIs, and REST endpoints) for Jupyter web applications like
Jupyter notebook, JupyterLab, and Voila.");

  script_tag(name:"affected", value:"'python-jupyter-server' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-jupyter-server", rpm:"python-jupyter-server~2.1.0~3.fc38", rls:"FC38"))) {
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