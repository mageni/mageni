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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3371");
  script_cve_id("CVE-2020-28935", "CVE-2022-30698", "CVE-2022-30699", "CVE-2022-3204");
  script_tag(name:"creation_date", value:"2023-04-11 04:27:48 +0000 (Tue, 11 Apr 2023)");
  script_version("2023-04-11T10:10:11+0000");
  script_tag(name:"last_modification", value:"2023-04-11 10:10:11 +0000 (Tue, 11 Apr 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 19:32:00 +0000 (Wed, 28 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-3371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3371");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3371");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/unbound");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unbound' package(s) announced via the DLA-3371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in unbound, a validating, recursive, caching DNS resolver.

CVE-2022-3204

A vulnerability named 'Non-Responsive Delegation Attack' (NRDelegation Attack) has been discovered in various DNS resolving software. The NRDelegation Attack works by having a malicious delegation with a considerable number of non responsive nameservers. The attack starts by querying a resolver for a record that relies on those unresponsive nameservers. The attack can cause a resolver to spend a lot of time/resources resolving records under a malicious delegation point where a considerable number of unresponsive NS records reside. It can trigger high CPU usage in some resolver implementations that continually look in the cache for resolved NS records in that delegation. This can lead to degraded performance and eventually denial of service in orchestrated attacks. Unbound does not suffer from high CPU usage, but resources are still needed for resolving the malicious delegation. Unbound will keep trying to resolve the record until hard limits are reached. Based on the nature of the attack and the replies, different limits could be reached. From now on Unbound introduces fixes for better performance when under load, by cutting opportunistic queries for nameserver discovery and DNSKEY prefetching and limiting the number of times a delegation point can issue a cache lookup for missing records.

CVE-2022-30698

and CVE-2022-30699

Unbound is vulnerable to a novel type of the ghost domain names attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a rogue domain name when the cached delegation information is about to expire. The rogue nameserver delays the response so that the cached delegation information is expired. Upon receiving the delayed answer containing the delegation information, Unbound overwrites the now expired entries. This action can be repeated when the delegation information is about to expire making the rogue delegation information ever-updating. From now on Unbound stores the start time for a query and uses that to decide if the cached delegation information can be overwritten.

CVE-2020-28935

Unbound contains a local vulnerability that would allow for a local symlink attack.

For Debian 10 buster, these problems have been fixed in version 1.9.0-2+deb10u3.

We recommend that you upgrade your unbound packages.

For the detailed security status of unbound please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'unbound' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunbound8", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-unbound", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-unbound", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound-anchor", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound-host", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound", ver:"1.9.0-2+deb10u3", rls:"DEB10"))) {
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
