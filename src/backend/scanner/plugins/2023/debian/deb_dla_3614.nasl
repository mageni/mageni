# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3614");
  script_cve_id("CVE-2022-48560", "CVE-2022-48564", "CVE-2022-48565", "CVE-2022-48566", "CVE-2023-40217");
  script_tag(name:"creation_date", value:"2023-10-12 04:35:23 +0000 (Thu, 12 Oct 2023)");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 13:36:00 +0000 (Fri, 01 Sep 2023)");

  script_name("Debian: Security Advisory (DLA-3614)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3614");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3614");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python3.7");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python3.7' package(s) announced via the DLA-3614 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Python 3.7.

CVE-2022-48560

A use-after-free problem was found in the heappushpop function in the heapq module.

CVE-2022-48564

A potential denial-of-service vulnerability was discovered in the read_ints function used when processing certain malformed Apple Property List files in binary format.

CVE-2022-48565

An XML External Entity (XXE) issue was discovered. In order to avoid possible vulnerabilities, the plistlib module no longer accepts entity declarations in XML plist files.

CVE-2022-48566

Possible constant-time-defeating compiler optimisations were discovered in the accumulator variable in hmac.compare_digest.

CVE-2023-40217

It was discovered that it might be possible to bypass some of the protections implemented by the TLS handshake in the ssl.SSLSocket class. For example, unauthenticated data might be read by a program expecting data authenticated by client certificates.

For Debian 10 buster, these problems have been fixed in version 3.7.3-2+deb10u6.

We recommend that you upgrade your python3.7 packages.

For the detailed security status of python3.7 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python3.7' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python3.7", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-dbg", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-dev", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-minimal", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-stdlib", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-testsuite", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-dbg", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-dev", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-doc", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-examples", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-venv", ver:"3.7.3-2+deb10u6", rls:"DEB10"))) {
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
