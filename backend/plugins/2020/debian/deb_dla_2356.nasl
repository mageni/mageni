# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892356");
  script_version("2020-08-30T03:00:47+0000");
  script_cve_id("CVE-2014-0791", "CVE-2020-11042", "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11048", "CVE-2020-11058", "CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-31 09:58:56 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-30 03:00:47 +0000 (Sun, 30 Aug 2020)");
  script_name("Debian LTS: Security Advisory for freerdp (DLA-2356-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00054.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2356-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp'
  package(s) announced via the DLA-2356-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been reported against FreeRDP, an Open Source
server and client implementation of the Microsoft RDP protocol.

CVE-2014-0791

An integer overflow in the license_read_scope_list function in
libfreerdp/core/license.c in FreeRDP allowed remote RDP
servers to cause a denial of service (application crash) or possibly
have unspecified other impact via a large ScopeCount value in a Scope
List in a Server License Request packet.

CVE-2020-11042

In FreeRDP there was an out-of-bounds read in update_read_icon_info.
It allowed reading an attacker-defined amount of client memory (32bit
unsigned -> 4GB) to an intermediate buffer. This could have been used
to crash the client or store information for later retrieval.

CVE-2020-11045

In FreeRDP there was an out-of-bound read in in
update_read_bitmap_data that allowed client memory to be read to an
image buffer. The result displayed on screen as colour.

CVE-2020-11046

In FreeRDP there was a stream out-of-bounds seek in
update_read_synchronize that could have lead to a later out-of-bounds
read.

CVE-2020-11048

In FreeRDP there was an out-of-bounds read. It only allowed to abort
a session. No data extraction was possible.

CVE-2020-11058

In FreeRDP, a stream out-of-bounds seek in
rdp_read_font_capability_set could have lead to a later out-of-bounds
read. As a result, a manipulated client or server might have forced a
disconnect due to an invalid data read.

CVE-2020-11521

libfreerdp/codec/planar.c in FreeRDP had an Out-of-bounds Write.

CVE-2020-11522

libfreerdp/gdi/gdi.c in FreeRDP had an Out-of-bounds Read.

CVE-2020-11523

libfreerdp/gdi/region.c in FreeRDP had an Integer Overflow.

CVE-2020-11525

libfreerdp/cache/bitmap.c in FreeRDP had an Out of bounds read.

CVE-2020-11526

libfreerdp/core/update.c in FreeRDP had an Out-of-bounds Read.

CVE-2020-13396

An out-of-bounds (OOB) read vulnerability has been detected in
ntlm_read_ChallengeMessage in
winpr/libwinpr/sspi/NTLM/ntlm_message.c.

CVE-2020-13397

An out-of-bounds (OOB) read vulnerability has been detected in
security_fips_decrypt in libfreerdp/core/security.c due to an
uninitialized value.

CVE-2020-13398

An out-of-bounds (OOB) write vulnerability has been detected in
crypto_rsa_common in libfreerdp/crypto/crypto.c.");

  script_tag(name:"affected", value:"'freerdp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4.

We recommend that you upgrade your freerdp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-cache1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-codec1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-common1.1.0", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-core1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-crypto1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-gdi1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-locale1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-primitives1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-rail1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-utils1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-asn1-0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-bcrypt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credentials0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credui0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crypto0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dsparse0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-environment0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-error0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-file0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-handle0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-heap0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-input0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-interlocked0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-io0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-library0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-path0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pipe0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pool0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-registry0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-rpc0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspi0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspicli0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-synch0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sysinfo0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-thread0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-timezone0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-utils0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winhttp0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winsock0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
