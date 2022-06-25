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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0323");
  script_cve_id("CVE-2016-5287", "CVE-2016-5288", "CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5297", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077", "CVE-2016-9078", "CVE-2016-9080", "CVE-2016-9893", "CVE-2016-9894", "CVE-2016-9895", "CVE-2016-9896", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903", "CVE-2016-9904", "CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5393", "CVE-2017-5396");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 18:29:00 +0000 (Mon, 30 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0323");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0323.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21637");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-87/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-91/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-94/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-01/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, iceape' package(s) announced via the MGASA-2017-0323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated Iceape packages include security fixes from upstream Seamonkey:

Multiple flaws were found in the way Iceape 2.46 processes various types
of web content, where loading a web page containing malicious content
could cause Iceape to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2016-5287, CVE-2016-5288, CVE-2016-5289,
CVE-2016-5290, CVE-2016-5292, CVE-2016-5297, CVE-2016-9064,
CVE-2016-9066, CVE-2016-9067, CVE-2016-9068, CVE-2016-9075,
CVE-2016-9077, CVE-2016-5291, CVE-2016-9063, CVE-2016-9070,
CVE-2016-9071, CVE-2016-9073, CVE-2016-9076, CVE-2016-9078,
CVE-2016-9080, CVE-2016-9893, CVE-2016-9894, CVE-2016-9895,
CVE-2016-9896, CVE-2016-9897, CVE-2016-9898, CVE-2016-9899,
CVE-2016-9900, CVE-2016-9901, CVE-2016-9902, CVE-2016-9903,
CVE-2016-9904, CVE-2017-5373, CVE-2017-5374, CVE-2017-5375,
CVE-2017-5376, CVE-2017-5377, CVE-2017-5378, CVE-2017-5379,
CVE-2017-5380, CVE-2017-5381, CVE-2017-5382, CVE-2017-5383,
CVE-2017-5384, CVE-2017-5385, CVE-2017-5386, CVE-2017-5387,
CVE-2017-5388, CVE-2017-5389, CVE-2017-5390, CVE-2017-5391,
CVE-2017-5393, CVE-2017-5396)");

  script_tag(name:"affected", value:"'iceape, iceape' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.48~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.48~1.mga6", rls:"MAGEIA6"))) {
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
