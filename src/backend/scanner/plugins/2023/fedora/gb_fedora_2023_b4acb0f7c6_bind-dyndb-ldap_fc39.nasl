# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885153");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-3341", "CVE-2023-4236");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 15:15:00 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:27 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for bind-dyndb-ldap (FEDORA-2023-b4acb0f7c6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b4acb0f7c6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5PIES3BNC75AGCDPNHEPESYL7DHIE5ZU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind-dyndb-ldap'
  package(s) announced via the FEDORA-2023-b4acb0f7c6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package provides an LDAP back-end plug-in for BIND. It features
support for dynamic updates and internal caching, to lift the load
off of your LDAP server.");

  script_tag(name:"affected", value:"'bind-dyndb-ldap' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~11.10~21.fc39", rls:"FC39"))) {
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