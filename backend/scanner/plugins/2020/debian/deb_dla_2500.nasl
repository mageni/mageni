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
  script_oid("1.3.6.1.4.1.25623.1.0.892500");
  script_version("2020-12-19T04:00:25+0000");
  script_cve_id("CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-12-19 04:00:25 +0000 (Sat, 19 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-19 04:00:25 +0000 (Sat, 19 Dec 2020)");
  script_name("Debian LTS: Security Advisory for curl (DLA-2500-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2500-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/977161");
  script_xref(name:"URL", value:"https://bugs.debian.org/977162");
  script_xref(name:"URL", value:"https://bugs.debian.org/977163");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the DLA-2500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in curl, a command line tool for
transferring data with URL syntax and an easy-to-use client-side URL
transfer library.

CVE-2020-8284

When curl performs a passive FTP transfer, it first tries the EPSV
command and if that is not supported, it falls back to using PASV.
Passive mode is what curl uses by default. A server response to a
PASV command includes the (IPv4) address and port number for the
client to connect back to in order to perform the actual data
transfer. This is how the FTP protocol is designed to work. A
malicious server can use the PASV response to trick curl into
connecting back to a given IP address and port, and this way
potentially make curl extract information about services that are
otherwise private and not disclosed, for example doing port scanning
and service banner extractions.

The IP address part of the response is now ignored by default, by
making CURLOPT_FTP_SKIP_PASV_IP default to 1L instead of previously
being 0L. This has the minor drawback that a small fraction of use
cases might break, when a server truly needs the client to connect
back to a different IP address than what the control connection uses
and for those CURLOPT_FTP_SKIP_PASV_IP can be set to 0L. The same
goes for the command line tool, which then might need --no-ftp-skip-pasv-ip
set to prevent curl from ignoring the address in the server response.

CVE-2020-8285

libcurl offers a wildcard matching functionality, which allows a
callback (set with CURLOPT_CHUNK_BGN_FUNCTION) to return information
back to libcurl on how to handle a specific entry in a directory
when libcurl iterates over a list of all available entries. When
this callback returns CURL_CHUNK_BGN_FUNC_SKIP, to tell libcurl to
not deal with that file, the internal function in libcurl then calls
itself recursively to handle the next directory entry. If there's a
sufficient amount of file entries and if the callback returns 'skip'
enough number of times, libcurl runs out of stack space. The exact
amount will of course vary with platforms, compilers and other
environmental factors. The content of the remote directory is not
kept on the stack, so it seems hard for the attacker to control
exactly what data that overwrites the stack - however it remains a
Denial-Of-Service vector as a malicious user who controls a server
that a libcurl-using application works with under these premises can
trigger a crash.

The internal function is rewritten to instead and more appropriately
use an ordinary loop instead of the recursive approach. This way,
the stack use will remain the same no matter how many files that are
skipped.

CVE-202 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
7.52.1-5+deb9u13.

We recommend that you upgrade your curl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.52.1-5+deb9u13", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
