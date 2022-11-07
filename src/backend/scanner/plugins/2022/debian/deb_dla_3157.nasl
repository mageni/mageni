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
  script_oid("1.3.6.1.4.1.25623.1.0.893157");
  script_version("2022-10-25T10:13:35+0000");
  script_cve_id("CVE-2019-8921", "CVE-2019-8922", "CVE-2021-41229", "CVE-2021-43400", "CVE-2022-0204", "CVE-2022-39176", "CVE-2022-39177");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-10-25 10:13:35 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-08 17:32:00 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2022-10-25 01:00:14 +0000 (Tue, 25 Oct 2022)");
  script_name("Debian LTS: Security Advisory for bluez (DLA-3157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/10/msg00026.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3157-1");
  script_xref(name:"Advisory-ID", value:"DLA-3157-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/998626");
  script_xref(name:"URL", value:"https://bugs.debian.org/1000262");
  script_xref(name:"URL", value:"https://bugs.debian.org/1003712");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez'
  package(s) announced via the DLA-3157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BlueZ, the Linux Bluetooth
protocol stack. An attacker could cause a denial-of-service (DoS) or
leak information.

CVE-2019-8921

SDP infoleak, the vulnerability lies in the handling of a
SVC_ATTR_REQ by the SDP implementation of BlueZ. By crafting a
malicious CSTATE, it is possible to trick the server into
returning more bytes than the buffer actually holds, resulting in
leaking arbitrary heap data.

CVE-2019-8922

SDP Heap Overflow, this vulnerability lies in the SDP protocol
handling of attribute requests as well. By requesting a huge
number of attributes at the same time, an attacker can overflow
the static buffer provided to hold the response.

CVE-2021-41229

sdp_cstate_alloc_buf allocates memory which will always be hung in
the singly linked list of cstates and will not be freed. This will
cause a memory leak over time. The data can be a very large
object, which can be caused by an attacker continuously sending
sdp packets and this may cause the service of the target device to
crash.

CVE-2021-43400

A use-after-free in gatt-database.c can occur when a client
disconnects during D-Bus processing of a WriteValue call.

CVE-2022-0204

A heap overflow vulnerability was found in bluez. An attacker with
local network access could pass specially crafted files causing an
application to halt or crash, leading to a denial of service.

CVE-2022-39176

BlueZ allows physically proximate attackers to obtain sensitive
information because profiles/audio/avrcp.c does not validate
params_len.

CVE-2022-39177

BlueZ allows physically proximate attackers to cause a denial of
service because malformed and invalid capabilities can be
processed in profiles/audio/avdtp.c.");

  script_tag(name:"affected", value:"'bluez' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.50-1.2~deb10u3.

We recommend that you upgrade your bluez packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.50-1.2~deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
