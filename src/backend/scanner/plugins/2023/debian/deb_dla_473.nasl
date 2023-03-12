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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.473");
  script_cve_id("CVE-2016-4476", "CVE-2016-4477");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 13:13:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-473");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DLA-473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in how hostapd and wpa_supplicant writes the configuration file update for the WPA/WPA2 passphrase parameter. If this parameter has been updated to include control characters either through a WPS operation (CVE-2016-4476) or through local configuration change over the wpa_supplicant control interface (CVE-2016-4477), the resulting configuration file may prevent the hostapd and wpa_supplicant from starting when the updated file is used. In addition for wpa_supplicant, it may be possible to load a local library file and execute code from there with the same privileges under which the wpa_supplicant process runs.

CVE-2016-4476

hostapd 0.6.7 through 2.5 and wpa_supplicant 0.6.7 through 2.5 do not reject n and r characters in passphrase parameters, which allows remote attackers to cause a denial of service (daemon outage) via a crafted WPS operation.

CVE-2016-4477

wpa_supplicant 0.4.0 through 2.5 does not reject n and r characters in passphrase parameters, which allows local users to trigger arbitrary library loading and consequently gain privileges, or cause a denial of service (daemon outage), via a crafted (1) SET, (2) SET_CRED, or (3) SET_NETWORK command.

For Debian 7 Wheezy, these problems have been fixed in version 1.0-3+deb7u4.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:1.0-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"1.0-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"1.0-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"1.0-3+deb7u4", rls:"DEB7"))) {
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
