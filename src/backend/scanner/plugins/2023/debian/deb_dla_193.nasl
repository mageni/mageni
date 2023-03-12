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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.193");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:52:00 +0000 (Tue, 17 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-193");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-193");
  script_xref(name:"URL", value:"https://www.eecis.udel.edu/~mills/onwire.html,");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chrony' package(s) announced via the DLA-193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2015-1853

Protect authenticated symmetric NTP associations against DoS attacks.

An attacker knowing that NTP hosts A and B are peering with each other (symmetric association) can send a packet with random timestamps to host A with source address of B which will set the NTP state variables on A to the values sent by the attacker. Host A will then send on its next poll to B a packet with originate timestamp that doesn't match the transmit timestamp of B and the packet will be dropped. If the attacker does this periodically for both hosts, they won't be able to synchronize to each other. It is a denial-of-service attack.

According to [link moved to references] NTP authentication is supposed to protect symmetric associations against this attack, but in the NTPv3 (RFC 1305) and NTPv4 (RFC 5905) specifications the state variables are updated before the authentication check is performed, which means the association is vulnerable to the attack even when authentication is enabled.

To fix this problem, save the originate and local timestamps only when the authentication check (test5) passed.

CVE-2015-1821

Fix access configuration with subnet size indivisible by 4.

When NTP or cmdmon access was configured (from chrony.conf or via authenticated cmdmon) with a subnet size that is indivisible by 4 and an address that has nonzero bits in the 4-bit subnet remainder (e.g. 192.168.15.0/22 or f000::/3), the new setting was written to an incorrect location, possibly outside the allocated array.

An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process.

CVE-2015-1822

Fix initialization of reply slots for authenticated commands.

When allocating memory to save unacknowledged replies to authenticated command requests, the last next pointer was not initialized to NULL. When all allocated reply slots were used, the next reply could be written to an invalid memory instead of allocating a new slot for it.

An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process.");

  script_tag(name:"affected", value:"'chrony' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chrony", ver:"1.24-3+squeeze2", rls:"DEB6"))) {
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
