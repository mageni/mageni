# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6467.2");
  script_cve_id("CVE-2023-36054");
  script_tag(name:"creation_date", value:"2023-11-07 04:08:48 +0000 (Tue, 07 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 17:57:23 +0000 (Tue, 15 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6467-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6467-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6467-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-6467-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6467-1 fixed a vulnerability in Kerberos. This update provides the
corresponding update for Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu
23.04.

Original advisory details:

 Robert Morris discovered that Kerberos did not properly handle memory
 access when processing RPC data through kadmind, which could lead to the
 freeing of uninitialized memory. An authenticated remote attacker could
 possibly use this issue to cause kadmind to crash, resulting in a denial
 of service.");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-otp", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt-mit11", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv-mit11", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdb5-9", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrad0", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.17-6ubuntu4.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-otp", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt-mit12", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv-mit12", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdb5-10", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrad0", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.19.2-2ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-otp", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt-mit12", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv-mit12", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdb5-10", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrad0", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.20.1-1ubuntu0.1", rls:"UBUNTU23.04"))) {
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
