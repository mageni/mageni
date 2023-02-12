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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5308.1");
  script_cve_id("CVE-2019-13115", "CVE-2019-17498", "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-5308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5308-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5308-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2' package(s) announced via the USN-5308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libssh2 mishandled certain input. If libssh2 were
used to connect to a malicious or compromised SSH server, a remote,
unauthenticated attacker could possibly execute arbitrary code on the client
system. (CVE-2019-3855)

It was discovered that libssh2 incorrectly handled prompt requests. A
remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2019-3856)

It was discovered that libssh2 incorrectly handled SSH_MSG_CHANNEL_REQUEST
packets. A remote attacker could possibly use this issue to execute
arbitrary code, cause a denial of service, or obtain sensitive information.
(CVE-2019-3857, CVE-2019-3862)

It was discovered that libssh2 incorrectly handled specially crafted SFTP
packets. A remote attacker could possibly use this issue to cause a denial
of service or obtain sensitive information. (CVE-2019-3858)

It was discovered that libssh2 incorrectly handled certain specially
crafted packets. A remote attacker could possibly use this issue to cause a
denial of service or obtain sensitive information. (CVE-2019-3859)

It was discovered that libssh2 incorrectly handled SFTP packets with empty
payloads. A remote attacker could possibly use this issue to cause a denial
of service or obtain sensitive information. (CVE-2019-3860)

It was discovered that libssh2 incorrectly handled padding values in SSH
packets. A remote attacker could possibly use this issue to cause a denial
of service or obtain sensitive information. (CVE-2019-3861)

It was discovered that libssh2 incorrectly handled interactive response
messages length. A remote attacker could possibly use this issue to execute
arbitrary code. (CVE-2019-3863)

It was discovered that libssh2 incorrectly handled the Diffie Hellman key
exchange. A remote attacker could possibly use this issue to cause a denial
of service or obtain sensitive information. (CVE-2019-13115)

It was discovered that libssh2 incorrectly handled bound checks in
SSH_MSG_DISCONNECT. A remote attacker could possibly use this issue to
cause a denial of service or obtain sensitive information. (CVE-2019-17498)");

  script_tag(name:"affected", value:"'libssh2' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1", ver:"1.5.0-2ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
