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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0468");
  script_cve_id("CVE-2019-14870", "CVE-2021-3671", "CVE-2021-44758", "CVE-2022-3437", "CVE-2022-41916", "CVE-2022-42898", "CVE-2022-44640");
  script_tag(name:"creation_date", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_version("2022-12-19T04:12:36+0000");
  script_tag(name:"last_modification", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 20:12:00 +0000 (Fri, 18 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0468)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0468");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0468.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31172");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5286");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5287");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3206");
  script_xref(name:"URL", value:"https://github.com/heimdal/heimdal/security/advisories/GHSA-q77c-9qvp-qfw4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/AYXWFESBZJMBNACFDHWWH7KETGKUXDPO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal' package(s) announced via the MGASA-2022-0468 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Isaac Boukris reported that the Heimdal KDC before 7.7.1 does not apply
delegation_not_allowed (aka not-delegated) user attributes for S4U2Self.
Instead the forwardable flag is set even if the impersonated client has
the not-delegated flag set. (CVE-2019-14870)

Joseph Sutton discovered that the Heimdal KDC before 7.7.1 does not check
for missing missing sname in TGS-REQ (Ticket Granting Server Request)
before before dereferencing. An authenticated user could use this flaw to
crash the KDC. (CVE-2021-3671)

It was discovered that Heimdal is prone to a NULL dereference in acceptors
when the initial SPNEGO token has no acceptable mechanisms, which may
result in denial of service for a server application that uses the Simple
and Protected GSSAPI Negotiation Mechanism (SPNEGO). (CVE-2021-44758)

Evgeny Legerov reported that the DES and Triple-DES decryption routines in
the Heimdal GSSAPI library before 7.7.1 were prone to buffer overflow on
malloc() allocated memory when presented with a maliciously small packet.
In addition, the Triple-DES and RC4 (arcfour) decryption routine were
prone to non-constant time leaks, which could potentially yield to a leak
of secret key material when using these ciphers. (CVE-2022-3437)

It was discovered that Heimdal's PKI certificate validation library before
7.7.1 can under some circumstances perform an out-of-bounds memory access
when normalizing Unicode, which may result in denial of service. (CVE-2022-41916)

Greg Hudson discovered an integer multiplication overflow in the Privilege
Attribute Certificate (PAC) parsing routine, which may result in denial of
service for Heimdal KDCs and possibly Heimdal servers (e.g., via GSS-API)
on 32-bit systems. (CVE-2022-42898)

Douglas Bagnall and the Heimdal maintainers independently discovered that
Heimdal's ASN.1 compiler before 7.7.1 generates code that allows specially
crafted DER encodings of CHOICEs to invoke the wrong free() function on the
decoded structure upon decode error, which may result in remote code
execution in the Heimdal KDC and possibly the Kerberos client, the X.509
library, and other components as well. (CVE-2022-44640)");

  script_tag(name:"affected", value:"'heimdal' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"heimdal", rpm:"heimdal~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-devel", rpm:"heimdal-devel~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-devel-doc", rpm:"heimdal-devel-doc~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-libs", rpm:"heimdal-libs~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-server", rpm:"heimdal-server~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-workstation", rpm:"heimdal-workstation~7.7.1~1.2.mga8", rls:"MAGEIA8"))) {
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
