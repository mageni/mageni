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
  script_oid("1.3.6.1.4.1.25623.1.0.891866");
  script_version("2019-08-01T02:00:09+0000");
  script_cve_id("CVE-2018-16428", "CVE-2018-16429", "CVE-2019-12450", "CVE-2019-13012");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-01 02:00:09 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 02:00:09 +0000 (Thu, 01 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1866-1] glib2.0 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1866-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/931234");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0'
  package(s) announced via the DSA-1866-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various minor issues have been addressed in the GLib library. GLib is a
useful general-purpose C library used by projects such as GTK+, GIMP,
and GNOME.

CVE-2018-16428

In GNOME GLib, g_markup_parse_context_end_parse() in gmarkup.c
had a NULL pointer dereference.

CVE-2018-16429

GNOME GLib had an out-of-bounds read vulnerability in
g_markup_parse_context_parse() in gmarkup.c, related to utf8_str().

CVE-2019-13012

The keyfile settings backend in GNOME GLib (aka glib2.0) before
created directories using g_file_make_directory_with_parents
(kfsb->dir, NULL, NULL) and files using g_file_replace_contents
(kfsb->file, contents, length, NULL, FALSE,
G_FILE_CREATE_REPLACE_DESTINATION, NULL, NULL, NULL). Consequently,
it did not properly restrict directory (and file) permissions.
Instead, for directories, 0777 permissions were used, for files,
default file permissions were used. This issue is similar to
CVE-2019-12450.");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.42.1-1+deb8u2.

We recommend that you upgrade your glib2.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0-refdbg", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-tests", ver:"2.42.1-1+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);