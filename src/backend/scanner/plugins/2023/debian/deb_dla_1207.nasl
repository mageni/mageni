# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.1207");
  script_cve_id("CVE-2017-1000385");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1207)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1207");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1207");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'erlang' package(s) announced via the DLA-1207 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An erlang TLS server configured with cipher suites using RSA key exchange, may be vulnerable to an Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack) against RSA, which when exploited, may result in plaintext recovery of encrypted messages and/or a Man-in-the-middle (MiTM) attack, despite the attacker not having gained access to the server's private key itself.

For Debian 7 Wheezy, these problems have been fixed in version 15.b.1-dfsg-4+deb7u2.

We recommend that you upgrade your erlang packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'erlang' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"erlang-appmon", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-corba", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dev", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-doc", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-et", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-examples", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-gs", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic-java", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inets", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inviso", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mode", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-nox", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-observer", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-percept", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-pman", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-src", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-test-server", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-toolbar", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tools", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tv", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-typer", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-webtool", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-wx", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-x11", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:15.b.1-dfsg-4+deb7u2", rls:"DEB7"))) {
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
