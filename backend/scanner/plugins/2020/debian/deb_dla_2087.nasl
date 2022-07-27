# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892087");
  script_version("2020-01-31T04:00:08+0000");
  script_cve_id("CVE-2019-18625", "CVE-2019-18792");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 04:00:08 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-31 04:00:08 +0000 (Fri, 31 Jan 2020)");
  script_name("Debian LTS: Security Advisory for suricata (DLA-2087-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2087-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'suricata'
  package(s) announced via the DLA-2087-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have recently been discovered in the stream-tcp code
of the intrusion detection and prevention tool Suricata.

CVE-2019-18625

It was possible to bypass/evade any tcp based signature by faking a
closed TCP session using an evil server. After the TCP SYN packet, it
was possible to inject a RST ACK and a FIN ACK packet with a bad TCP
Timestamp option. The client would have ignored the RST ACK and the
FIN ACK packets because of the bad TCP Timestamp option.

CVE-2019-18792

It was possible to bypass/evade any tcp based signature by
overlapping a TCP segment with a fake FIN packet. The fake FIN packet
had to be injected just before the PUSH ACK packet we wanted to
bypass. The PUSH ACK packet (containing the data) would have been
ignored by Suricata because it would have overlapped the FIN packet
(the sequence and ack number are identical in the two packets). The
client would have ignored the fake FIN packet because the ACK flag
would not have been set.");

  script_tag(name:"affected", value:"'suricata' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.0.7-2+deb8u5.

We recommend that you upgrade your suricata packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"suricata", ver:"2.0.7-2+deb8u5", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
