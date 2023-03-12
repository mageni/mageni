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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2345");
  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2345");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2345");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Icedove, a mail client based on Thunderbird.

CVE-2011-3647

The JSSubScriptLoader does not properly handle XPCNativeWrappers during calls to the loadSubScript method in an add-on, which makes it easier for remote attackers to gain privileges via a crafted web site that leverages certain unwrapping behavior.

CVE-2011-3648

A cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML via crafted text with Shift JIS encoding.

CVE-2011-3650

Iceweasel does not properly handle JavaScript files that contain many functions, which allows user-assisted remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via a crafted file that is accessed by debugging APIs, as demonstrated by Firebug.

For the stable distribution (squeeze), these problems have been fixed in version 3.0.11-1+squeeze6.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 3.1.15-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze6", rls:"DEB6"))) {
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
