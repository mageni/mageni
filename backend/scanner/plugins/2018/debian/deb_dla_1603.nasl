###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1603.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1603-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891603");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-15377", "CVE-2017-7177", "CVE-2018-6794");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1603-1] suricata security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-05 00:00:00 +0100 (Wed, 05 Dec 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"suricata on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.0.7-2+deb8u3.

We recommend that you upgrade your suricata packages.");
  script_tag(name:"summary", value:"Several issues were found in suricata, an intrusion detection and
prevention tool.

CVE-2017-7177

Suricata has an IPv4 defragmentation evasion issue caused by lack
of a check for the IP protocol during fragment matching.

CVE-2017-15377

It was possible to trigger lots of redundant checks on the content
of crafted network traffic with a certain signature, because of
DetectEngineContentInspection in detect-engine-content-inspection.c.
The search engine doesn't stop when it should after no match is
found. Instead, it stops only upon reaching inspection-recursion-
limit (3000 by default).

CVE-2018-6794

Suricata is prone to an HTTP detection bypass vulnerability in
detect.c and stream-tcp.c. If a malicious server breaks a normal
TCP flow and sends data before the 3-way handshake is complete,
then the data sent by the malicious server will be accepted by web
clients such as a web browser or Linux CLI utilities, but ignored
by Suricata IDS signatures. This mostly affects IDS signatures for
the HTTP protocol and TCP stream content. Signatures for TCP packets
will inspect such network traffic as usual.

TEMP-0856648-2BC2C9 (no CVE assigned yet)

Out of bounds read in app-layer-dns-common.c.
On a zero size A or AAAA record, 4 or 16 bytes would still be read.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  # TODO: Re-Check the TEMP assignment above in a few weeks.

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"suricata", ver:"2.0.7-2+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}