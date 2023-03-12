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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2357");
  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643", "CVE-2011-5244");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2357)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2357");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2357");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evince' package(s) announced via the DSA-2357 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jon Larimer from IBM X-Force Advanced Research discovered multiple vulnerabilities in the DVI backend of the Evince document viewer:

CVE-2010-2640

Insufficient array bounds checks in the PK fonts parser could lead to function pointer overwrite, causing arbitrary code execution.

CVE-2010-2641

Insufficient array bounds checks in the VF fonts parser could lead to function pointer overwrite, causing arbitrary code execution.

CVE-2010-2642

Insufficient bounds checks in the AFM fonts parser when writing data to a memory buffer allocated on heap could lead to arbitrary memory overwrite and arbitrary code execution.

CVE-2010-2643

Insufficient check on an integer used as a size for memory allocation can lead to arbitrary write outside the allocated range and cause arbitrary code execution.

For the oldstable distribution (lenny), this problem has been fixed in version 2.22.2-4~lenny2.

For the stable distribution (squeeze), CVE-2010-2640, CVE-2010-2641 and CVE-2010-2643 have been fixed in version 2.30.3-2 but the fix for CVE-2010-2642 was incomplete. The final fix is present in version 2.30.3-2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 3.0.2-1.

For the unstable distribution (sid), this problem has been fixed in version 3.0.2-1.

We recommend that you upgrade your evince packages.");

  script_tag(name:"affected", value:"'evince' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"evince-dbg", ver:"2.22.2-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-gtk-dbg", ver:"2.22.2-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-gtk", ver:"2.22.2-4~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince", ver:"2.22.2-4~lenny2", rls:"DEB5"))) {
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
