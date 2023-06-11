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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3441");
  script_cve_id("CVE-2023-32307");
  script_tag(name:"creation_date", value:"2023-06-05 04:21:35 +0000 (Mon, 05 Jun 2023)");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3441)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3441");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3441");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sofia-sip' package(s) announced via the DLA-3441 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a series of heap overflow and integer overflow vulnerabilities in Sofia-SIP, a building block for creating VoIP/SIP and instant messaging applications.

CVE-2023-32307

Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. Referring to GHSA-8599-x7rq-fr54 several other potential heap-over-flow and integer-overflow in stun_parse_attr_error_code and stun_parse_attr_uint32 were found because the lack of attributes length check when Sofia-SIP handles STUN packets. The previous patch of GHSA-8599-x7rq-fr54 fixed the vulnerability when attr_type did not match the enum value, but there are also vulnerabilities in the handling of other valid cases. The OOB read and integer-overflow made by attacker may lead to crash, high consumption of memory or even other more serious consequences. These issue have been addressed in version 1.13.15. Users are advised to upgrade.

For Debian 10 Buster, this problem has been fixed in version 1.12.11+20110422.1-2.1+deb10u4.

We recommend that you upgrade your sofia-sip packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sofia-sip' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-dev", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib-dev", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib3", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua0", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-bin", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-doc", ver:"1.12.11+20110422.1-2.1+deb10u4", rls:"DEB10"))) {
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
