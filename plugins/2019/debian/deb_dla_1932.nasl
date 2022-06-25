# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891932");
  script_version("2019-09-26T02:00:39+0000");
  script_cve_id("CVE-2019-1547", "CVE-2019-1563");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-26 02:00:39 +0000 (Thu, 26 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-26 02:00:39 +0000 (Thu, 26 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1932-1] openssl security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00026.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1932-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the DSA-1932-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities were found in OpenSSL, the Secure Sockets
Layer toolkit.

CVE-2019-1547

Normally in OpenSSL EC groups always have a co-factor present and
this is used in side channel resistant code paths. However, in some
cases, it is possible to construct a group using explicit parameters
(instead of using a named curve). In those cases it is possible that
such a group does not have the cofactor present. This can occur even
where all the parameters match a known named curve. If such a curve
is used then OpenSSL falls back to non-side channel resistant code
paths which may result in full key recovery during an ECDSA
signature operation. In order to be vulnerable an attacker
would have to have the ability to time the creation of a large
number of signatures where explicit parameters with no co-factor
present are in use by an application using libcrypto. For the
avoidance of doubt libssl is not vulnerable because explicit
parameters are never used.

CVE-2019-1563

In situations where an attacker receives automated notification of
the success or failure of a decryption attempt an attacker, after
sending a very large number of messages to be decrypted, can recover
a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted
message that was encrypted with the public RSA key, using a
Bleichenbacher padding oracle attack. Applications are not affected
if they use a certificate together with the private RSA key to the
CMS_decrypt or PKCS7_decrypt functions to select the correct
recipient info to decrypt.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.0.1t-1+deb8u12.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1t-1+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1t-1+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1t-1+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1t-1+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1t-1+deb8u12", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);