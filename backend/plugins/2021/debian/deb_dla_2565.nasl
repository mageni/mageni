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
  script_oid("1.3.6.1.4.1.25623.1.0.892565");
  script_version("2021-02-19T07:31:47+0000");
  script_cve_id("CVE-2021-23840", "CVE-2021-23841");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-19 11:47:28 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-19 04:00:30 +0000 (Fri, 19 Feb 2021)");
  script_name("Debian LTS: Security Advisory for openssl1.0 (DLA-2565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2565-1");
  script_xref(name:"Advisory-ID", value:"DLA-2565-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl1.0'
  package(s) announced via the DLA-2565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two issues in the 1.0 branch of the
OpenSSL cryptographic system:

  * CVE-2021-23840: Prevent an issue where 'Digital EnVeloPe'
EVP-related calls could cause applications to behave incorrectly
or even crash.

  * CVE-2021-23841: Prevent an issue in the X509 certificate
handling caused by the lack of error handling whilst parsing
'issuer' fields.");

  script_tag(name:"affected", value:"'openssl1.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', these problems have been fixed in version
1.0.2u-1~deb9u4. For the equivalent changes for the 1.1 branch of
OpenSSL, please see DLA-2563-1.

We recommend that you upgrade your openssl1.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0-dev", ver:"1.0.2u-1~deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.2", ver:"1.0.2u-1~deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
