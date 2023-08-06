# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3491");
  script_cve_id("CVE-2022-37026");
  script_tag(name:"creation_date", value:"2023-07-12 04:29:37 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 18:05:00 +0000 (Fri, 23 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-3491)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3491");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3491");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/erlang");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'erlang' package(s) announced via the DLA-3491 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Client Authentication Bypass vulnerability has been discovered in the concurrent, real-time, distributed functional language Erlang. Impacted are those who are running an ssl/tls/dtls server using the ssl application either directly or indirectly via other applications. Note that the vulnerability only affects servers that request client certification, that is sets the option {verify, verify_peer}.

Additionally the source package elixir-lang has been rebuilt against the new erlang version. The rabbitmq-server package was upgraded to version 3.8.2 to fix an incompatibility with Erlang 22.

For Debian 10 buster, this problem has been fixed in version 1:22.2.7+dfsg-1+deb10u1.

We recommend that you upgrade your erlang packages.

For the detailed security status of erlang please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'erlang' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dev", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-doc", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-et", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-examples", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ftp", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inets", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mode", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-nox", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-observer", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-src", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tftp", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tools", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-wx", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-x11", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:22.2.7+dfsg-1+deb10u1", rls:"DEB10"))) {
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
