# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5521");
  script_cve_id("CVE-2023-28709", "CVE-2023-41080", "CVE-2023-42795", "CVE-2023-44487", "CVE-2023-45648");
  script_tag(name:"creation_date", value:"2023-10-11 04:24:23 +0000 (Wed, 11 Oct 2023)");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5521");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5521");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5521");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tomcat10");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat10' package(s) announced via the DSA-5521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat servlet and JSP engine.

CVE-2023-28709

Denial of Service. If non-default HTTP connector settings were used such that the maxParameterCount could be reached using query string parameters and a request was submitted that supplied exactly maxParameterCount parameters in the query string, the limit for uploaded request parts could be bypassed with the potential for a denial of service to occur.

CVE-2023-41080

Open redirect. If the ROOT (default) web application is configured to use FORM authentication then it is possible that a specially crafted URL could be used to trigger a redirect to an URL of the attackers choice.

CVE-2023-42795

Information Disclosure. When recycling various internal objects, including the request and the response, prior to re-use by the next request/response, an error could cause Tomcat to skip some parts of the recycling process leading to information leaking from the current request/response to the next.

CVE-2023-44487

DoS caused by HTTP/2 frame overhead (Rapid Reset Attack)

CVE-2023-45648

Request smuggling. Tomcat did not correctly parse HTTP trailer headers. A specially crafted, invalid trailer header could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

For the stable distribution (bookworm), these problems have been fixed in version 10.1.6-1+deb12u1.

We recommend that you upgrade your tomcat10 packages.

For the detailed security status of tomcat10 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tomcat10' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat10-embed-java", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat10-java", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10-admin", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10-common", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10-docs", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10-examples", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10-user", ver:"10.1.6-1+deb12u1", rls:"DEB12"))) {
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
