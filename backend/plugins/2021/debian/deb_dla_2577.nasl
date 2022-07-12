# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892577");
  script_version("2021-02-27T04:00:09+0000");
  script_cve_id("CVE-2017-1000433", "CVE-2021-21239");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-01 11:32:23 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-02-27 04:00:09 +0000 (Sat, 27 Feb 2021)");
  script_name("Debian LTS: Security Advisory for python-pysaml2 (DLA-2577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00038.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2577-1");
  script_xref(name:"Advisory-ID", value:"DLA-2577-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/886423");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pysaml2'
  package(s) announced via the DLA-2577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in python-pysaml2, a pure python
implementation of SAML Version 2 Standard.

CVE-2017-1000433

pysaml2 accept any password when run with python optimizations
enabled. This allows attackers to log in as any user without
knowing their password.

CVE-2021-21239

pysaml2 has an improper verification of cryptographic signature
vulnerability. Users of pysaml2 that use the default
CryptoBackendXmlSec1 backend and need to verify signed SAML
documents are impacted. PySAML2 does not ensure that a signed
SAML document is correctly signed. The default
CryptoBackendXmlSec1 backend is using the xmlsec1 binary to
verify the signature of signed SAML documents, but by default
xmlsec1 accepts any type of key found within the given document.
xmlsec1 needs to be configured explicitly to only use only _x509
certificates_ for the verification process of the SAML document signature.");

  script_tag(name:"affected", value:"'python-pysaml2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.0.0-5+deb9u2.

We recommend that you upgrade your python-pysaml2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-pysaml2", ver:"3.0.0-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-pysaml2-doc", ver:"3.0.0-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-pysaml2", ver:"3.0.0-5+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
