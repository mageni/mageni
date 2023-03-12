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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2104");
  script_cve_id("CVE-2010-2948", "CVE-2010-2949");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2104)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2104");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2104");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-2104 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the BGP implementation of Quagga, a routing daemon.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2948

When processing a crafted Route Refresh message received from a configured, authenticated BGP neighbor, Quagga may crash, leading to a denial of service.

CVE-2010-2949

When processing certain crafted AS paths, Quagga would crash with a NULL pointer dereference, leading to a denial of service. In some configurations, such crafted AS paths could be relayed by intermediate BGP routers.

In addition, this update contains a reliability fix: Quagga will no longer advertise confederation-related AS paths to non-confederation peers, and reject unexpected confederation-related AS paths by resetting the session with the BGP peer which is advertising them. (Previously, such AS paths would trigger resets of unrelated BGP sessions.)

For the stable distribution (lenny), these problems have been fixed in version 0.99.10-1lenny3.

For the unstable distribution (sid) and the testing distribution (squeeze), these problems have been fixed in version 0.99.17-1.

We recommend that you upgrade your quagga package.");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.10-1lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.10-1lenny3", rls:"DEB5"))) {
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
