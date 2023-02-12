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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4796.1");
  script_cve_id("CVE-2016-7099", "CVE-2017-1000381", "CVE-2018-12115", "CVE-2018-12116", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-7160", "CVE-2018-7167", "CVE-2019-5737");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4796-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4796-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4796-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-4796-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Minozhenko and James Bunton discovered that Node.js did not
properly handle wildcards in name fields of X.509 TLS certificates. An
attacker could use this vulnerability to execute a machine-in-the-middle-
attack. This issue only affected Ubuntu 14.04 ESM and 16.04 ESM. (CVE-2016-7099)

It was discovered that Node.js incorrectly handled certain NAPTR responses.
A remote attacker could possibly use this issue to cause applications using
Node.js to crash, resulting in a denial of service. This issue only affected
Ubuntu 16.04 ESM. (CVE-2017-1000381)

Nikita Skovoroda discovered that Node.js mishandled certain input, leading
to an out of bounds write. An attacker could use this vulnerability to
cause a denial of service (crash) or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 ESM. (CVE-2018-12115)

Arkadiy Tetelman discovered that Node.js improperly handled certain
malformed HTTP requests. An attacker could use this vulnerability to inject
unexpected HTTP requests. This issue only affected Ubuntu 18.04 ESM.
(CVE-2018-12116)

Jan Maybach discovered that Node.js did not time out if incomplete
HTTP/HTTPS headers were received. An attacker could use this vulnerability
to cause a denial of service by keeping HTTP/HTTPS connections alive for a
long period of time. This issue only affected Ubuntu 18.04 ESM.
(CVE-2018-12122)

Martin Bajanik discovered that the url.parse() method would return
incorrect results if it received specially crafted input. An attacker could
use this vulnerability to spoof the hostname and bypass hostname-specific
security controls. This issue only affected Ubuntu 18.04 ESM. (CVE-2018-12123)

It was discovered that Node.js is vulnerable to a DNS rebinding attack which
could be exploited to perform remote code execution. An attack is possible
from malicious websites open in a web browser with network access to the system
running the Node.js process. This issue only affected Ubuntu 18.04 ESM.
(CVE-2018-7160)

It was discovered that the Buffer.fill() and Buffer.alloc() methods
improperly handled certain inputs. An attacker could use this vulnerability
to cause a denial of service. This issue only affected Ubuntu 18.04 ESM.
(CVE-2018-7167)

Marco Pracucci discovered that Node.js mishandled HTTP and HTTPS
connections. An attacker could use this vulnerability to cause a denial of
service. This issue only affected Ubuntu 18.04 ESM. (CVE-2019-5737)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"0.10.25~dfsg2-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-legacy", ver:"0.10.25~dfsg2-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"0.10.25~dfsg2-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"4.2.6~dfsg-1ubuntu4.2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-legacy", ver:"4.2.6~dfsg-1ubuntu4.2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"4.2.6~dfsg-1ubuntu4.2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"8.10.0~dfsg-2ubuntu0.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"8.10.0~dfsg-2ubuntu0.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"8.10.0~dfsg-2ubuntu0.4+esm1", rls:"UBUNTU18.04 LTS"))) {
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
