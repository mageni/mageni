# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6038.2");
  script_cve_id("CVE-2022-1705", "CVE-2022-1962", "CVE-2022-27664", "CVE-2022-28131", "CVE-2022-2879", "CVE-2022-2880", "CVE-2022-29526", "CVE-2022-30629", "CVE-2022-30630", "CVE-2022-30631", "CVE-2022-30632", "CVE-2022-30633", "CVE-2022-30635", "CVE-2022-32148", "CVE-2022-32189", "CVE-2022-41715", "CVE-2022-41717", "CVE-2023-24534", "CVE-2023-24537", "CVE-2023-24538");
  script_tag(name:"creation_date", value:"2024-01-10 04:09:13 +0000 (Wed, 10 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-17 16:54:18 +0000 (Mon, 17 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6038-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6038-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6038-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.13, golang-1.16' package(s) announced via the USN-6038-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6038-1 fixed several vulnerabilities in Go 1.18. This update provides
the corresponding updates for Go 1.13 and Go 1.16.

CVE-2022-29526 and CVE-2022-30630 only affected Go 1.16.

Original advisory details:

 It was discovered that the Go net/http module incorrectly handled
 Transfer-Encoding headers in the HTTP/1 client. A remote attacker could
 possibly use this issue to perform an HTTP Request Smuggling attack.
 (CVE-2022-1705)

 It was discovered that Go did not properly manage memory under certain
 circumstances. An attacker could possibly use this issue to cause a panic
 resulting into a denial of service. (CVE-2022-1962, CVE-2022-27664,
 CVE-2022-28131, CVE-2022-30630, CVE-2022-30631, CVE-2022-30632,
 CVE-2022-30633, CVE-2022-30635, CVE-2022-32189, CVE-2022-41715,
 CVE-2022-41717, CVE-2023-24534, CVE-2023-24537)

 It was discovered that Go did not properly implemented the maximum size of
 file headers in Reader.Read. An attacker could possibly use this issue to
 cause a panic resulting into a denial of service. (CVE-2022-2879)

 It was discovered that the Go net/http module incorrectly handled query
 parameters in requests forwarded by ReverseProxy. A remote attacker could
 possibly use this issue to perform an HTTP Query Parameter Smuggling attack.
 (CVE-2022-2880)

 It was discovered that Go did not properly manage the permissions for
 Faccessat function. A attacker could possibly use this issue to expose
 sensitive information. (CVE-2022-29526)

 It was discovered that Go did not properly generate the values for
 ticket_age_add in session tickets. An attacker could possibly use this
 issue to observe TLS handshakes to correlate successive connections by
 comparing ticket ages during session resumption. (CVE-2022-30629)

 It was discovered that Go did not properly manage client IP addresses in
 net/http. An attacker could possibly use this issue to cause ReverseProxy
 to set the client IP as the value of the X-Forwarded-For header.
 (CVE-2022-32148)

 It was discovered that Go did not properly validate backticks (`) as
 Javascript string delimiters, and do not escape them as expected. An
 attacker could possibly use this issue to inject arbitrary Javascript code
 into the Go template. (CVE-2023-24538)");

  script_tag(name:"affected", value:"'golang-1.13, golang-1.16' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13", ver:"1.13.8-1ubuntu1~16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-go", ver:"1.13.8-1ubuntu1~16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-src", ver:"1.13.8-1ubuntu1~16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13", ver:"1.13.8-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-go", ver:"1.13.8-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-src", ver:"1.13.8-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16", ver:"1.16.2-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16-go", ver:"1.16.2-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16-src", ver:"1.16.2-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13", ver:"1.13.8-1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-go", ver:"1.13.8-1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-src", ver:"1.13.8-1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16", ver:"1.16.2-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16-go", ver:"1.16.2-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.16-src", ver:"1.16.2-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13", ver:"1.13.8-1ubuntu2.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-go", ver:"1.13.8-1ubuntu2.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.13-src", ver:"1.13.8-1ubuntu2.22.04.2", rls:"UBUNTU22.04 LTS"))) {
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
