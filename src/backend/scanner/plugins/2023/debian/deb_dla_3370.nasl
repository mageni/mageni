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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3370");
  script_cve_id("CVE-2022-23468", "CVE-2022-23478", "CVE-2022-23479", "CVE-2022-23483", "CVE-2022-23484", "CVE-2022-23493");
  script_tag(name:"creation_date", value:"2023-03-31 04:23:14 +0000 (Fri, 31 Mar 2023)");
  script_version("2023-03-31T10:08:37+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:37 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-10 02:15:00 +0000 (Sat, 10 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3370)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3370");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3370");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xrdp");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xrdp' package(s) announced via the DLA-3370 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several out of bounds memory access and buffer overflows were fixed in xrdp, an open source project which provides a graphical login to remote machines using Microsoft Remote Desktop Protocol (RDP)

CVE-2022-23468

xrdp < v0.9.21 contain a buffer over flow in xrdp_login_wnd_create() function. There are no known workarounds for this issue.

CVE-2022-23478

xrdp < v0.9.21 contain a Out of Bound Write in xrdp_mm_trans_process_drdynvc_channel_open() function. There are no known workarounds for this issue.

CVE-2022-23479

xrdp < v0.9.21 contain a buffer over flow in xrdp_mm_chan_data_in() function. There are no known workarounds for this issue.

CVE-2022-23483

xrdp < v0.9.21 contain a Out of Bound Read in libxrdp_send_to_channel() function. There are no known workarounds for this issue.

CVE-2022-23484

xrdp < v0.9.21 contain a Integer Overflow in xrdp_mm_process_rail_update_window_text() function. There are no known workarounds for this issue.

CVE-2022-23493

xrdp < v0.9.21 contain a Out of Bound Read in xrdp_mm_trans_process_drdynvc_channel_close() function. There are no known workarounds for this issue.

For Debian 10 buster, these problems have been fixed in version 0.9.9-1+deb10u2.

We recommend that you upgrade your xrdp packages.

For the detailed security status of xrdp please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'xrdp' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xrdp", ver:"0.9.9-1+deb10u2", rls:"DEB10"))) {
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
