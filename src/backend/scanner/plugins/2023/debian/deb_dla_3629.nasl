# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3629");
  script_cve_id("CVE-2019-10222", "CVE-2020-10753", "CVE-2020-12059", "CVE-2020-1700", "CVE-2020-1760", "CVE-2020-25678", "CVE-2020-27781", "CVE-2021-20288", "CVE-2021-3524", "CVE-2021-3531", "CVE-2021-3979", "CVE-2023-43040");
  script_tag(name:"creation_date", value:"2023-10-24 04:23:36 +0000 (Tue, 24 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 18:56:54 +0000 (Wed, 29 Apr 2020)");

  script_name("Debian: Security Advisory (DLA-3629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3629-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3629-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ceph");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ceph' package(s) announced via the DLA-3629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were fixed in Ceph, a massively scalable, open-source, distributed storage system that runs on commodity hardware and delivers object, block and file system storage.

CVE-2019-10222

A Denial of service was fixed: An unauthenticated attacker could crash the Ceph RGW server by sending valid HTTP headers and terminating the connection, resulting in a remote denial of service for Ceph RGW clients.

CVE-2020-1700

A Denial of Service was fixed: A flaw was found in the way the Ceph RGW Beast front-end handles unexpected disconnects. An authenticated attacker can abuse this flaw by making multiple disconnect attempts resulting in a permanent leak of a socket connection by radosgw. This flaw could lead to a denial of service condition by pile up of CLOSE_WAIT sockets, eventually leading to the exhaustion of available resources, preventing legitimate users from connecting to the system.

CVE-2020-1760

A XSS attack was fixed: A flaw was found in the Ceph Object Gateway, where it supports request sent by an anonymous user in Amazon S3. This flaw could lead to potential XSS attacks due to the lack of proper neutralization of untrusted input.

CVE-2020-10753

A Header Injection attack was fixed: It was possible to inject HTTP headers via a CORS ExposeHeader tag in an Amazon S3 bucket. The newline character in the ExposeHeader tag in the CORS configuration file generates a header injection in the response when the CORS request is made.

CVE-2020-12059

A Denial of Service was fixed: A POST request with an invalid tagging XML could crash the RGW process by triggering a NULL pointer exception.

CVE-2020-25678

An Information Disclosure was fixed: ceph stores mgr module passwords in clear text. This can be found by searching the mgr logs for grafana and dashboard, with passwords visible.

CVE-2020-27781

A Privilege Escalation was fixed: User credentials could be manipulated and stolen by Native CephFS consumers of OpenStack Manila, resulting in potential privilege escalation. An Open Stack Manila user can request access to a share to an arbitrary cephx user, including existing users. The access key is retrieved via the interface drivers. Then, all users of the requesting OpenStack project can view the access key. This enables the attacker to target any resource that the user has access to. This can be done to even admin users, compromising the ceph administrator.

CVE-2021-3524

Similar to CVE-2020-10753, a Header Injection attack was fixed: It was possible to inject HTTP headers via a CORS ExposeHeader tag in an Amazon S3 bucket

CVE-2021-3531

A Denial of Service was fixed: When processing a GET Request in Ceph Storage RGW for a swift URL that ends with two slashes it could cause the rgw to crash, resulting in a denial of service.

CVE-2021-3979

A Loss of Confidentiality was fixed: A key length flaw was found in Ceph Storage. An attacker could exploit the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ceph' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-test", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ceph", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-cephfs", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rados", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rbd", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rgw", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"12.2.11+dfsg1-2.1+deb10u1", rls:"DEB10"))) {
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
