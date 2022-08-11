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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0283");
  script_cve_id("CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662", "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666", "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670", "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675", "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679", "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683", "CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5812", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5816", "CVE-2019-5817", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823", "CVE-2019-5824", "CVE-2019-5825", "CVE-2019-5826", "CVE-2019-5827", "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840", "CVE-2019-5842", "CVE-2019-5847", "CVE-2019-5848", "CVE-2019-5849", "CVE-2019-5850", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5853", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5858", "CVE-2019-5859", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5863", "CVE-2019-5864", "CVE-2019-5865", "CVE-2019-5866", "CVE-2019-5867", "CVE-2019-5868", "CVE-2019-5869", "CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5873", "CVE-2019-5874", "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877", "CVE-2019-5878", "CVE-2019-5879", "CVE-2019-5880", "CVE-2019-5881");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0283");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0283.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23558");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_23.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/05/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/05/stable-channel-update-for-desktop_21.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop_18.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/07/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/07/stable-channel-update-for-desktop_30.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/08/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/08/stable-channel-update-for-desktop_26.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/09/stable-channel-update-for-desktop.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2019-0283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in the way Chromium 73.0.3683.103 processes
various types of web content, where loading a web page containing
malicious content could cause Chromium to crash, execute arbitrary code,
or disclose sensitive information. (CVE-2019-5805, CVE-2019-5806,
CVE-2019-5807, CVE-2019-5808, CVE-2019-5809, CVE-2019-5810,
CVE-2019-5811, CVE-2019-5812, CVE-2019-5813, CVE-2019-5814,
CVE-2019-5815, CVE-2019-5816, CVE-2019-5817, CVE-2019-5818,
CVE-2019-5819, CVE-2019-5820, CVE-2019-5821, CVE-2019-5822,
CVE-2019-5823, CVE-2019-5824, CVE-2019-5825, CVE-2019-5826,
CVE-2019-5827, CVE-2019-5828, CVE-2019-5829, CVE-2019-5830,
CVE-2019-5831, CVE-2019-5832, CVE-2019-5833, CVE-2019-5834,
CVE-2019-5835, CVE-2019-5836, CVE-2019-5837, CVE-2019-5838,
CVE-2019-5839, CVE-2019-5840, CVE-2019-5842, CVE-2019-5847,
CVE-2019-5848, CVE-2019-5849, CVE-2019-5850, CVE-2019-5851,
CVE-2019-5852, CVE-2019-5853, CVE-2019-5854, CVE-2019-5855,
CVE-2019-5856, CVE-2019-5857, CVE-2019-5858, CVE-2019-5859,
CVE-2019-5860, CVE-2019-5861, CVE-2019-5862, CVE-2019-5863,
CVE-2019-5864, CVE-2019-5865, CVE-2019-5866, CVE-2019-5867,
CVE-2019-5868, CVE-2019-5869, CVE-2019-5870, CVE-2019-5871,
CVE-2019-5872, CVE-2019-5873, CVE-2019-5874, CVE-2019-5875,
CVE-2019-5876, CVE-2019-5877, CVE-2019-5878, CVE-2019-5879,
CVE-2019-5880, CVE-2019-5881, CVE-2019-13659, CVE-2019-13660,
CVE-2019-13661, CVE-2019-13662, CVE-2019-13663, CVE-2019-13664,
CVE-2019-13665, CVE-2019-13666, CVE-2019-13667, CVE-2019-13668,
CVE-2019-13669, CVE-2019-13670, CVE-2019-13671, CVE-2019-13673,
CVE-2019-13674, CVE-2019-13675, CVE-2019-13676, CVE-2019-13677,
CVE-2019-13678, CVE-2019-13679, CVE-2019-13680, CVE-2019-13681,
CVE-2019-13682, CVE-2019-13683)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~77.0.3865.75~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~77.0.3865.75~1.mga7", rls:"MAGEIA7"))) {
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
