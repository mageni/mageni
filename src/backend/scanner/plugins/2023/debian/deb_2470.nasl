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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2012.2470");
  script_cve_id("CVE-2011-3122", "CVE-2011-3125", "CVE-2011-3126", "CVE-2011-3127", "CVE-2011-3128", "CVE-2011-3129", "CVE-2011-3130", "CVE-2011-4956", "CVE-2011-4957", "CVE-2012-2399", "CVE-2012-2400", "CVE-2012-2401", "CVE-2012-2402", "CVE-2012-2403", "CVE-2012-2404");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2470)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2470");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2470");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-2470 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were identified in WordPress, a web blogging tool. As the CVEs were allocated from releases announcements and specific fixes are usually not identified, it has been decided to upgrade the wordpress package to the latest upstream version instead of backporting the patches.

This means extra care should be taken when upgrading, especially when using third-party plugins or themes, since compatibility may have been impacted along the way. We recommend that users check their install before doing the upgrade.

For the stable distribution (squeeze), those problems have been fixed in version 3.3.2+dfsg-1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), those problems have been fixed in version 3.3.2+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.3.2+dfsg-1~squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.3.2+dfsg-1~squeeze1", rls:"DEB6"))) {
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
