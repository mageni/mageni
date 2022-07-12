###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1445.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1445-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891445");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2011-5325", "CVE-2013-1813", "CVE-2014-4607", "CVE-2014-9645", "CVE-2015-9261",
                "CVE-2015-9621", "CVE-2016-2147", "CVE-2016-2148", "CVE-2017-15873", "CVE-2017-16544",
                "CVE-2018-1000517");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1445-1] busybox security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-27 00:00:00 +0200 (Fri, 27 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00037.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"busybox on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:1.22.0-9+deb8u2.

We recommend that you upgrade your busybox packages.");
  script_tag(name:"summary", value:"Busybox, utility programs for small and embedded systems, was affected
by several security vulnerabilities. The Common Vulnerabilities and
Exposures project identifies the following issues.

CVE-2011-5325

A path traversal vulnerability was found in Busybox implementation
of tar. tar will extract a symlink that points outside of the
current working directory and then follow that symlink when
extracting other files. This allows for a directory traversal
attack when extracting untrusted tarballs.

CVE-2013-1813

When device node or symlink in /dev should be created inside
2-or-deeper subdirectory (/dev/dir1/dir2.../node), the intermediate
directories are created with incorrect permissions.

CVE-2014-4607

An integer overflow may occur when processing any variant of a
'literal run' in the lzo1x_decompress_safe function. Each of these
three locations is subject to an integer overflow when processing
zero bytes. This exposes the code that copies literals to memory
corruption.

CVE-2014-9645

The add_probe function in modutils/modprobe.c in BusyBox allows
local users to bypass intended restrictions on loading kernel
modules via a / (slash) character in a module name, as demonstrated
by an 'ifconfig /usbserial up' command or a 'mount -t /snd_pcm none
/' command.

CVE-2016-2147

Integer overflow in the DHCP client (udhcpc) in BusyBox allows
remote attackers to cause a denial of service (crash) via a
malformed RFC1035-encoded domain name, which triggers an
out-of-bounds heap write.

CVE-2016-2148

Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox
allows remote attackers to have unspecified impact via vectors
involving OPTION_6RD parsing.

CVE-2017-15873

The get_next_block function in archival/libarchive
/decompress_bunzip2.c in BusyBox has an Integer Overflow that may
lead to a write access violation.

CVE-2017-16544

In the add_match function in libbb/lineedit.c in BusyBox, the tab
autocomplete feature of the shell, used to get a list of filenames
in a directory, does not sanitize filenames and results in executing
any escape sequence in the terminal. This could potentially result
in code execution, arbitrary file writes, or other attacks.

CVE-2018-1000517

BusyBox contains a Buffer Overflow vulnerability in
Busybox wget that can result in a heap-based buffer overflow.
This attack appears to be exploitable via network connectivity.

CVE-2015-9621

Unziping a specially crafted zip file results in a computation of an
invalid pointer and a crash reading an invalid address.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"busybox", ver:"1:1.22.0-9+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.22.0-9+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"busybox-syslogd", ver:"1:1.22.0-9+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udhcpc", ver:"1:1.22.0-9+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udhcpd", ver:"1:1.22.0-9+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}