# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884291");
  script_version("2023-12-08T05:05:53+0000");
  script_cve_id("CVE-2022-25147");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-08 05:05:53 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 19:42:00 +0000 (Wed, 17 May 2023)");
  script_tag(name:"creation_date", value:"2023-07-30 01:02:43 +0000 (Sun, 30 Jul 2023)");
  script_name("CentOS: Security Advisory for apr-util (CESA-2023:3145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:3145");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-July/086409.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr-util'
  package(s) announced via the CESA-2023:3145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. apr-util is a library which provides
additional utility interfaces for APR, including support for XML parsing,
LDAP, database interfaces, URI parsing, and more.

Security Fix(es):

  * apr-util: out-of-bounds writes in the apr_base64 (CVE-2022-25147)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'apr-util' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"apr-util", rpm:"apr-util~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-devel", rpm:"apr-util-devel~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-ldap", rpm:"apr-util-ldap~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-mysql", rpm:"apr-util-mysql~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-nss", rpm:"apr-util-nss~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-odbc", rpm:"apr-util-odbc~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-openssl", rpm:"apr-util-openssl~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-pgsql", rpm:"apr-util-pgsql~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-sqlite", rpm:"apr-util-sqlite~1.5.2~6.el7_9.1", rls:"CentOS7"))) {
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