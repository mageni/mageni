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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.478");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-478");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-478");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DLA-478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in the Squid caching proxy.

CVE-2016-4051

CESG and Yuriy M. Kaminskiy discovered that Squid cachemgr.cgi was vulnerable to a buffer overflow when processing remotely supplied inputs relayed through Squid.

CVE-2016-4052

CESG discovered that a buffer overflow made Squid vulnerable to a Denial of Service (DoS) attack when processing ESI responses.

CVE-2016-4053

CESG found that Squid was vulnerable to public information disclosure of the server stack layout when processing ESI responses.

CVE-2016-4054

CESG discovered that Squid was vulnerable to remote code execution when processing ESI responses.

CVE-2016-4554

Jianjun Chen found that Squid was vulnerable to a header smuggling attack that could lead to cache poisoning and to bypass of same-origin security policy in Squid and some client browsers.

CVE-2016-4555

and CVE-2016-4556

'bfek-18' and '@vftable' found that Squid was vulnerable to a Denial of Service (DoS) attack when processing ESI responses, due to incorrect pointer handling and reference counting.

For Debian 7 Wheezy, these issues have been fixed in squid3 version 3.1.20-2.2+deb7u5. We recommend you to upgrade your squid3 packages.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.20-2.2+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3-common", ver:"3.1.20-2.2+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.1.20-2.2+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.1.20-2.2+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.1.20-2.2+deb7u5", rls:"DEB7"))) {
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
