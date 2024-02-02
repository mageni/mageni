# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3717");
  script_cve_id("CVE-2023-32721", "CVE-2023-32723", "CVE-2023-32726");
  script_tag(name:"creation_date", value:"2024-01-25 04:21:20 +0000 (Thu, 25 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 15:08:25 +0000 (Tue, 17 Oct 2023)");

  script_name("Debian: Security Advisory (DLA-3717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3717-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3717-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zabbix' package(s) announced via the DLA-3717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'zabbix' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:4.0.4+dfsg-1+deb10u4", rls:"DEB10"))) {
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
