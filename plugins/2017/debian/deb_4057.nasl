###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4057.nasl 14284 2019-03-18 15:02:15Z cfischer $
#
# Auto-generated from advisory DSA 4057-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704057");
  script_version("$Revision: 14284 $");
  script_cve_id("CVE-2017-1000385");
  script_name("Debian Security Advisory DSA 4057-1 (erlang - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:02:15 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-12-08 00:00:00 +0100 (Fri, 08 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4057.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"erlang on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 1:17.3-dfsg-4+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 1:19.2.1+dfsg-2+deb9u1.

We recommend that you upgrade your erlang packages.

For the detailed security status of erlang please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/erlang");
  script_tag(name:"summary", value:"It was discovered that the TLS server in Erlang is vulnerable to an
adaptive chosen ciphertext attack against RSA keys.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"erlang", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-base", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-corba", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dbg", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dev", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-doc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-et", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-examples", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-gs", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ic", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ic-java", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-inets", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-mode", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-nox", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-observer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-percept", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-src", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-test-server", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-typer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-webtool", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-wx", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-x11", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-base", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-corba", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dbg", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dev", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-doc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-et", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-examples", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-gs", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ic", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ic-java", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-inets", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-mode", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-nox", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-observer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-percept", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-src", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-typer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-wx", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-x11", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}