# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891683");
  script_version("$Revision: 14300 $");
  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178",
                "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182", "CVE-2018-8791",
                "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796",
                "CVE-2018-8797", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1683-1] rdesktop security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 08:52:26 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-19 00:00:00 +0100 (Tue, 19 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00030.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"rdesktop on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.8.4-0+deb8u1.

We recommend that you upgrade your rdesktop packages.");
  script_tag(name:"summary", value:"Multiple security issues were found in the rdesktop RDP client, which
could result in denial of service, information disclosure and the
execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"rdesktop", ver:"1.8.4-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}