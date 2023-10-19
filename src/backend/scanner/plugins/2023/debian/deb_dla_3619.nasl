# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3619");
  script_cve_id("CVE-2020-11987", "CVE-2022-38398", "CVE-2022-38648", "CVE-2022-40146", "CVE-2022-44729", "CVE-2022-44730");
  script_tag(name:"creation_date", value:"2023-10-16 07:25:58 +0000 (Mon, 16 Oct 2023)");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-3619)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3619");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3619");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/batik");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'batik' package(s) announced via the DLA-3619 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Batik is a toolkit for applications or applets that want to use images in the Scalable Vector Graphics (SVG) format for various purposes, such as viewing, generation or manipulation.

CVE-2020-11987

A server-side request forgery was found, caused by improper input validation by the NodePickerPanel. By using a specially-crafted argument, an attacker could exploit this vulnerability to cause the underlying server to make arbitrary GET requests.

CVE-2022-38398

A Server-Side Request Forgery (SSRF) vulnerability was found that allows an attacker to load a url thru the jar protocol.

CVE-2022-38648

A Server-Side Request Forgery (SSRF) vulnerability was found that allows an attacker to fetch external resources.

CVE-2022-40146

A Server-Side Request Forgery (SSRF) vulnerability was found that allows an attacker to access files using a Jar url.

CVE-2022-44729

A Server-Side Request Forgery (SSRF) vulnerability was found. A malicious SVG could trigger loading external resources by default, causing resource consumption or in some cases even information disclosure.

CVE-2022-44730

A Server-Side Request Forgery (SSRF) vulnerability was found. A malicious SVG can probe user profile / data and send it directly as parameter to a URL.

For Debian 10 buster, these problems have been fixed in version 1.10-2+deb10u3.

We recommend that you upgrade your batik packages.

For the detailed security status of batik please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'batik' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbatik-java", ver:"1.10-2+deb10u3", rls:"DEB10"))) {
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
