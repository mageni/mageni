# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.352.1");
  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4570", "CVE-2006-4571");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-352-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-352-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird' package(s) announced via the USN-352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious email containing JavaScript. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable
it. (CVE-2006-4253, CVE-2006-4565, CVE-2006-4566, CVE-2006-4571)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Jon Oberheide reported a way how a remote attacker could trick users
into downloading arbitrary extensions with circumventing the normal
SSL certificate check. The attacker would have to be in a position to
spoof the victim's DNS, causing them to connect to sites of the
attacker's choosing rather than the sites intended by the victim. If
they gained that control and the victim accepted the attacker's cert
for the Mozilla update site, then the next update check could be
hijacked and redirected to the attacker's site without
detection. (CVE-2006-4567)

Georgi Guninski discovered that even with JavaScript disabled, a
malicious email could still execute JavaScript when the message is
viewed, replied to, or forwarded by putting the script in a remote XBL
file loaded by the message. (CVE-2006-4570)");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.7-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS"))) {
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
