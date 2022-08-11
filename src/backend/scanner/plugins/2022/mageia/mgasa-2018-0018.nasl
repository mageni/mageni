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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0018");
  script_cve_id("CVE-2016-10196", "CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5409", "CVE-2017-5410", "CVE-2017-5411", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5425", "CVE-2017-5426", "CVE-2017-5427", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469", "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7753", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7760", "CVE-2017-7761", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7766", "CVE-2017-7767", "CVE-2017-7768", "CVE-2017-7778", "CVE-2017-7779", "CVE-2017-7782", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7793", "CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7805", "CVE-2017-7807", "CVE-2017-7809", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7825", "CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7843", "CVE-2017-7845");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0018");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0018.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22283");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-05/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-12/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-16/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-19/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-22/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-25/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-28/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, iceape' package(s) announced via the MGASA-2018-0018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages include security fixes from upstream Seamonkey
and Firefox:

Multiple flaws were found in the way Iceape 2.48 processes various types
of web content, where loading a web page containing malicious content
could cause Iceape to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2016-10196,CVE-2017-5398,CVE-2017-5399,
CVE-2017-5400,CVE-2017-5401,CVE-2017-5402,CVE-2017-5403,CVE-2017-5404,
CVE-2017-5405,CVE-2017-5406,CVE-2017-5407,CVE-2017-5409,CVE-2017-5410,
CVE-2017-5411,CVE-2017-5408,CVE-2017-5412,CVE-2017-5413,CVE-2017-5414,
CVE-2017-5415,CVE-2017-5416,CVE-2017-5417,CVE-2017-5425,CVE-2017-5426,
CVE-2017-5427,CVE-2017-5418,CVE-2017-5419,CVE-2017-5420,CVE-2017-5421,
CVE-2017-5422,CVE-2017-5429,CVE-2017-5430,CVE-2017-5432,CVE-2017-5433,
CVE-2017-5434,CVE-2017-5435,CVE-2017-5436,CVE-2017-5438,CVE-2017-5439,
CVE-2017-5440,CVE-2017-5441,CVE-2017-5442,CVE-2017-5443,CVE-2017-5444,
CVE-2017-5445,CVE-2017-5446,CVE-2017-5447,CVE-2017-5448,CVE-2017-5449,
CVE-2017-5451,CVE-2017-5454,CVE-2017-5455,CVE-2017-5456,CVE-2017-5459,
CVE-2017-5460,CVE-2017-5461,CVE-2017-5462,CVE-2017-5464,CVE-2017-5465,
CVE-2017-5466,CVE-2017-5467,CVE-2017-5469,CVE-2017-5470,CVE-2017-5472,
CVE-2017-7749,CVE-2017-7750,CVE-2017-7751,CVE-2017-7752,CVE-2017-7753,
CVE-2017-7754,CVE-2017-7755,CVE-2017-7756,CVE-2017-7757,CVE-2017-7758,
CVE-2017-7760,CVE-2017-7761,CVE-2017-7763,CVE-2017-7764,CVE-2017-7765,
CVE-2017-7766,CVE-2017-7767,CVE-2017-7768,CVE-2017-7778,CVE-2017-7779,
CVE-2017-7782,CVE-2017-7784,CVE-2017-7785,CVE-2017-7786,CVE-2017-7787,
CVE-2017-7791,CVE-2017-7792,CVE-2017-7793,CVE-2017-7798,CVE-2017-7800,
CVE-2017-7801,CVE-2017-7802,CVE-2017-7803,CVE-2017-7804,CVE-2017-7805,
CVE-2017-7807,CVE-2017-7809,CVE-2017-7810,CVE-2017-7814,CVE-2017-7818,
CVE-2017-7819,CVE-2017-7823,CVE-2017-7824,CVE-2017-7825,CVE-2017-7826,
CVE-2017-7828,CVE-2017-7830,CVE-2017-7843,CVE-2017-7845)");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.49.1~3.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.49.1~3.mga6", rls:"MAGEIA6"))) {
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
