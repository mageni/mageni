# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892225");
  script_version("2020-05-31T03:00:12+0000");
  script_cve_id("CVE-2016-10198", "CVE-2017-5840");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-31 03:00:12 +0000 (Sun, 31 May 2020)");
  script_name("Debian LTS: Security Advisory for gst-plugins-good0.10 (DLA-2225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2225-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-good0.10'
  package(s) announced via the DLA-2225-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two memory handling issues were found in gst-plugins-good0.10, a
collection of GStreamer plugins from the 'good' set:

CVE-2016-10198

An invalid read can be triggered in the aacparse element via a
maliciously crafted file.

CVE-2017-5840

An out of bounds heap read can be triggered in the qtdemux element
via a maliciously crafted file.");

  script_tag(name:"affected", value:"'gst-plugins-good0.10' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.10.31-3+nmu4+deb8u3.

We recommend that you upgrade your gst-plugins-good0.10 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-gconf", ver:"0.10.31-3+nmu4+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good", ver:"0.10.31-3+nmu4+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-dbg", ver:"0.10.31-3+nmu4+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-doc", ver:"0.10.31-3+nmu4+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-pulseaudio", ver:"0.10.31-3+nmu4+deb8u3", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
