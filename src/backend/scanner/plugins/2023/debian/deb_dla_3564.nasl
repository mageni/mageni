# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3564");
  script_cve_id("CVE-2021-44273");
  script_tag(name:"creation_date", value:"2023-09-13 04:19:35 +0000 (Wed, 13 Sep 2023)");
  script_version("2023-09-13T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-11 17:50:00 +0000 (Tue, 11 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-3564)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3564");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3564");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'e2guardian' package(s) announced via the DLA-3564 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential Man In the Middle (MITM) vulnerability in e2guardian, a web content filtering engine.

Validation of SSL certificates was missing in e2guardian's own MITM prevention engine. In standalone mode (ie. acting as a proxy or a transparent proxy) with SSL MITM enabled, e2guardian did not validate hostnames in certificates of the web servers that it connected to, and thus was itself vulnerable to MITM attacks.

CVE-2021-44273

e2guardian v5.4.x <= v5.4.3r is affected by missing SSL certificate validation in the SSL MITM engine. In standalone mode (i.e., acting as a proxy or a transparent proxy), with SSL MITM enabled, e2guardian, if built with OpenSSL v1.1.x, did not validate hostnames in certificates of the web servers that it connected to, and thus was itself vulnerable to MITM attacks.

For Debian 10 Buster, this problem has been fixed in version 5.3.1-1+deb10u1.

We recommend that you upgrade your e2guardian packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'e2guardian' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"e2guardian", ver:"5.3.1-1+deb10u1", rls:"DEB10"))) {
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
