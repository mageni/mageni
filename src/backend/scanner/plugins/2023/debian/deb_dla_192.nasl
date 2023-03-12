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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.192");
  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 14:08:00 +0000 (Thu, 28 May 2020)");

  script_name("Debian: Security Advisory (DLA-192)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-192");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-192");
  script_xref(name:"URL", value:"https://www.eecis.udel.edu/~mills/onwire.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DLA-192 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2015-1798

When ntpd is configured to use a symmetric key to authenticate a remote NTP server/peer, it checks if the NTP message authentication code (MAC) in received packets is valid, but not if there actually is any MAC included. Packets without a MAC are accepted as if they had a valid MAC. This allows a MITM attacker to send false packets that are accepted by the client/peer without having to know the symmetric key. The attacker needs to know the transmit timestamp of the client to match it in the forged reply and the false reply needs to reach the client before the genuine reply from the server. The attacker doesn't necessarily need to be relaying the packets between the client and the server.

Authentication using autokey doesn't have this problem as there is a check that requires the key ID to be larger than NTP_MAXKEY, which fails for packets without a MAC.

CVE-2015-1799

An attacker knowing that NTP hosts A and B are peering with each other (symmetric association) can send a packet to host A with source address of B which will set the NTP state variables on A to the values sent by the attacker. Host A will then send on its next poll to B a packet with originate timestamp that doesn't match the transmit timestamp of B and the packet will be dropped. If the attacker does this periodically for both hosts, they won't be able to synchronize to each other. This is a known denial-of-service attack, described at [link moved to references] .

According to the document the NTP authentication is supposed to protect symmetric associations against this attack, but that doesn't seem to be the case. The state variables are updated even when authentication fails and the peers are sending packets with originate timestamps that don't match the transmit timestamps on the receiving side.

ntp-keygen on big endian hosts

Using ntp-keygen to generate an MD5 key on big endian hosts resulted in either an infite loop or an key of only 93 possible keys.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p2+dfsg-1+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p2+dfsg-1+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p2+dfsg-1+deb6u3", rls:"DEB6"))) {
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
