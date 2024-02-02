# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885627");
  script_version("2024-02-02T14:37:52+0000");
  script_cve_id("CVE-2024-22195");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 23:58:58 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-28 02:02:17 +0000 (Sun, 28 Jan 2024)");
  script_name("Fedora: Security Advisory for python-jinja2 (FEDORA-2024-604e4c3509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-604e4c3509");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DELCVUUYX75I5K4Q5WMJG4MUZJA6VAIP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-jinja2'
  package(s) announced via the FEDORA-2024-604e4c3509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jinja2 is a template engine written in pure Python. It provides a
Django inspired non-XML syntax but supports inline expressions and an
optional sandboxed environment.

If you have any exposure to other text-based template languages, such
as Smarty or Django, you should feel right at home with Jinja2. It&#39, s
both designer and developer friendly by sticking to Python&#39, s
principles and adding functionality useful for templating
environments.");

  script_tag(name:"affected", value:"'python-jinja2' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-jinja2", rpm:"python-jinja2~3.1.3~1.fc38", rls:"FC38"))) {
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