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
  script_oid("1.3.6.1.4.1.25623.1.0.891972");
  script_version("2019-10-27T03:00:13+0000");
  script_cve_id("CVE-2017-7655", "CVE-2018-12550", "CVE-2018-12551", "CVE-2019-11779");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-27 03:00:13 +0000 (Sun, 27 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-27 03:00:13 +0000 (Sun, 27 Oct 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1972-1] mosquitto security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/10/msg00035.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1972-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mosquitto'
  package(s) announced via the DSA-1972-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in mosquitto, a MQTT version 3.1/3.1.1
compatible message broker.

CVE-2017-7655

A Null dereference vulnerability in the Mosquitto library could
lead to crashes for those applications using the library.

CVE-2018-12550

An ACL file with no statements was treated as having a default
allow policy. The new behaviour of an empty ACL file is a default
policy of access denied.
(this is in compliance with all newer releases)

CVE-2018-12551

Malformed authentication data in the password file could allow
clients to circumvent authentication and get access to the broker.

CVE-2019-11779

Fix for processing a crafted SUBSCRIBE packet containing a topic
that consists of approximately 65400 or more '/' characters.
(setting TOPIC_HIERARCHY_LIMIT to 200)");

  script_tag(name:"affected", value:"'mosquitto' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.3.4-2+deb8u4.

We recommend that you upgrade your mosquitto packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libmosquitto-dev", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmosquitto1", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp-dev", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp1", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mosquitto-clients", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mosquitto-dbg", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-mosquitto", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-mosquitto", ver:"1.3.4-2+deb8u4", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);