# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5540");
  script_cve_id("CVE-2023-36478", "CVE-2023-44487");
  script_tag(name:"creation_date", value:"2023-10-31 04:23:14 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5540-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5540-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5540");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jetty9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jetty9' package(s) announced via the DSA-5540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two remotely exploitable security vulnerabilities were discovered in Jetty 9, a Java based web server and servlet engine. The HTTP/2 protocol implementation did not sufficiently verify if HPACK header values exceed their size limit. Furthermore the HTTP/2 protocol allowed a denial of service (server resource consumption) because request cancellation can reset many streams quickly. This problem is also known as Rapid Reset Attack.

For the oldstable distribution (bullseye), these problems have been fixed in version 9.4.50-4+deb11u1.

For the stable distribution (bookworm), these problems have been fixed in version 9.4.50-4+deb12u2.

We recommend that you upgrade your jetty9 packages.

For the detailed security status of jetty9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'jetty9' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.4.50-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.4.50-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.4.50-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.4.50-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.4.50-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.4.50-4+deb12u2", rls:"DEB12"))) {
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
