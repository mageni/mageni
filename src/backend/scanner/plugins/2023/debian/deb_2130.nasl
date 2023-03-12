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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2130");
  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2130");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2130");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in BIND, an implementation of the DNS protocol suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3762

When DNSSEC validation is enabled, BIND does not properly handle certain bad signatures if multiple trust anchors exist for a single zone, which allows remote attackers to cause a denial of service (server crash) via a DNS query.

CVE-2010-3614

BIND does not properly determine the security status of an NS RRset during a DNSKEY algorithm rollover, which may lead to zone unavailability during rollovers.

CVE-2010-3613

BIND does not properly handle the combination of signed negative responses and corresponding RRSIG records in the cache, which allows remote attackers to cause a denial of service (server crash) via a query for cached data.

In addition, this security update improves compatibility with previously installed versions of the bind9 package. As a result, it is necessary to initiate the update with 'apt-get dist-upgrade' instead of 'apt-get update'.

For the stable distribution (lenny), these problems have been fixed in version 1:9.6.ESV.R3+dfsg-0+lenny1.

For the upcoming stable distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1:9.7.2.dfsg.P3-1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-50", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns58", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc50", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc50", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg50", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres50", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.6.ESV.R3+dfsg-0+lenny1", rls:"DEB5"))) {
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
