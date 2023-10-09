# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3610");
  script_cve_id("CVE-2019-11236", "CVE-2019-11324", "CVE-2020-26137", "CVE-2023-43804");
  script_tag(name:"creation_date", value:"2023-10-09 04:24:08 +0000 (Mon, 09 Oct 2023)");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-3610)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3610");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3610");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python-urllib3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-urllib3' package(s) announced via the DLA-3610 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security vulnerabilities were found in python-urllib3, an HTTP library with thread-safe connection pooling for Python, which could lead to information disclosure or authorization bypass.

CVE-2019-11236

Hanno Bock discovered that an attacker controlling the request parameter can inject headers by injecting CR/LF chars. The issue is similar to CPython's CVE-2019-9740.

CVE-2019-11324

Christian Heimes discovered that when verifying HTTPS connections upon passing an SSLContext to urllib3, system CA certificates are loaded into the SSLContext by default in addition to any manually-specified CA certificates. This causes TLS handshakes that should fail given only the manually specified certs to succeed based on system CA certs.

CVE-2020-26137

It was discovered that CRLF injection was possible if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of putrequest(). The issue is similar to urllib's CVE-2020-26116.

CVE-2023-43804

It was discovered that the Cookie request header isn't stripped during cross-origin redirects. It is therefore possible for a user specifying a Cookie header to unknowingly leak information via HTTP redirects to a different origin (unless the user disables redirects explicitly). The issue is similar to CVE-2018-20060, but for Cookie request header rather than Authorization.

Moreover 'authorization' request headers were not removed redirecting to cross-site. Per RFC7230 sec. 3.2 header fields are to be treated case-insensitively.

For Debian 10 buster, these problems have been fixed in version 1.24.1-1+deb10u1.

We recommend that you upgrade your python-urllib3 packages.

For the detailed security status of python-urllib3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python-urllib3' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-urllib3", ver:"1.24.1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-urllib3", ver:"1.24.1-1+deb10u1", rls:"DEB10"))) {
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
