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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3380");
  script_cve_id("CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364", "CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2021-23168", "CVE-2021-23223", "CVE-2021-37409", "CVE-2021-44545", "CVE-2022-21181");
  script_tag(name:"creation_date", value:"2023-04-05 14:13:40 +0000 (Wed, 05 Apr 2023)");
  script_version("2023-04-06T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-04-06 10:08:49 +0000 (Thu, 06 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 19:52:00 +0000 (Fri, 19 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3380");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3380");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firmware-nonfree");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firmware-nonfree' package(s) announced via the DLA-3380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The firmware-nonfree package has been updated to include addtional firmware that may be requested by some drivers in Linux 5.10, availble for Debian LTS as backported kernel.

Some of the updated firmware files adresses security vulnerabilities, which may allow Escalation of Privileges, Denial of Services and Information Disclosures.

CVE-2020-24586

(INTEL-SA-00473)

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.

CVE-2020-24587

(INTEL-SA-00473)

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption key is periodically renewed.

CVE-2020-24588

(INTEL-SA-00473)

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an adversary can abuse this to inject arbitrary network packets.

CVE-2021-23168

(INTEL-SA-00621)

Out of bounds read for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-23223

(INTEL-SA-00621)

Improper initialization for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-37409

(INTEL-SA-00621)

Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-44545

(INTEL-SA-00621)

Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2022-21181

(INTEL-SA-00621)

Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

The following advisories are also fixed by this upload, but needs an updated Linux kernel to load the updated firmware:

CVE-2020-12362

(INTEL-SA-00438)

Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firmware-nonfree' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"firmware-adi", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-amd-graphics", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-atheros", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2x", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-brcm80211", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-cavium", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intel-sound", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intelwimax", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ipw2x00", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ivtv", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-iwlwifi", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-libertas", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux-nonfree", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-misc-nonfree", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-myricom", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-netronome", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-netxen", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-qcom-media", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-qlogic", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ralink", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-realtek", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-samsung", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-siano", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ti-connectivity", ver:"20190114+really20220913-0+deb10u1", rls:"DEB10"))) {
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
