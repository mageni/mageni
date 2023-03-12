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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.602");
  script_cve_id("CVE-2016-6313");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-602)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-602");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-602");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DLA-602 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-6313

Felix Doerre and Vladimir Klebanov from the Karlsruhe Institute of Technology discovered a flaw in the mixing functions of GnuPG's random number generator. An attacker who obtains 4640 bits from the RNG can trivially predict the next 160 bits of output.

A first analysis on the impact of this bug for GnuPG shows that existing RSA keys are not weakened. For DSA and Elgamal keys it is also unlikely that the private key can be predicted from other public information.

Bypassing GnuPG key checking Weaknesses have been found in GnuPG signature validation that attackers could exploit thanks to especially forged public keys and under specific hardware-software conditions. While the underlying problem cannot be solved only by software, GnuPG has been strengthened, avoiding to rely on keyring signature caches when verifying keys. Potential specific attacks are not valid any more with the patch of GnuPG

Bypassing GnuPG key checking: Vrije Universiteit Amsterdam and Katholieke Universteit Leuven researchers discovered an attack method, known as Flip Feng Shui, that concerns flaws in GnuPG. Researchers found that under specific hardware-software conditions, attackers could bypass the GnuPG signature validation by using forged public keys. While the underlying problem cannot be solved only by software, GnuPG has been made more robust to avoid relying on keyring signature caches when verifying keys.

For Debian 7 Wheezy, these issues have been addressed in version 1.4.12-7+deb7u8.

We recommend that you upgrade your gnupg packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-udeb", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-udeb", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv", ver:"1.4.12-7+deb7u8", rls:"DEB7"))) {
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
