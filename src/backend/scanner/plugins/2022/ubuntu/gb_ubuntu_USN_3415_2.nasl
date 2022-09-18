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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3415.2");
  script_cve_id("CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 19:28:00 +0000 (Wed, 28 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3415-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3415-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3415-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the USN-3415-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3415-1 fixed vulnerabilities in tcpdump for Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, and Ubuntu 17.04. This update provides the
corresponding tcpdump update for Ubuntu 12.04 ESM.

Original advisory details:

 Wilfried Kirsch discovered a buffer overflow in the SLIP decoder
 in tcpdump. A remote attacker could use this to cause a denial
 of service (application crash) or possibly execute arbitrary
 code. (CVE-2017-11543)

 Bhargava Shastry discovered a buffer overflow in the bitfield converter
 utility function bittok2str_internal() in tcpdump. A remote attacker
 could use this to cause a denial of service (application crash)
 or possibly execute arbitrary code. (CVE-2017-13011)

 Otto Airamo and Antti Levomaki discovered logic errors in different
 protocol parsers in tcpdump that could lead to an infinite loop. A
 remote attacker could use these to cause a denial of service
 (application hang). CVE-2017-12989, CVE-2017-12990, CVE-2017-12995,
 CVE-2017-12997)

 Otto Airamo, Brian Carpenter, Yannick Formaggio, Kamil Frankowicz,
 Katie Holly, Kim Gwan Yeong, Antti Levomaki, Henri Salo, and Bhargava
 Shastry discovered out-of-bounds reads in muliptle protocol parsers
 in tcpdump. A remote attacker could use these to cause a denial
 of service (application crash). (CVE-2017-11108, CVE-2017-11541,
 CVE-2017-11542, CVE-2017-12893, CVE-2017-12894, CVE-2017-12895,
 CVE-2017-12896, CVE-2017-12897, CVE-2017-12898, CVE-2017-12899,
 CVE-2017-12900, CVE-2017-12901, CVE-2017-12902, CVE-2017-12985,
 CVE-2017-12986, CVE-2017-12987, CVE-2017-12988, CVE-2017-12991,
 CVE-2017-12992, CVE-2017-12993, CVE-2017-12994, CVE-2017-12996,
 CVE-2017-12998, CVE-2017-12999, CVE-2017-13000, CVE-2017-13001,
 CVE-2017-13002, CVE-2017-13003, CVE-2017-13004, CVE-2017-13005,
 CVE-2017-13006, CVE-2017-13007, CVE-2017-13008, CVE-2017-13009,
 CVE-2017-13010, CVE-2017-13012, CVE-2017-13013, CVE-2017-13014,
 CVE-2017-13015, CVE-2017-13016, CVE-2017-13017, CVE-2017-13018,
 CVE-2017-13019, CVE-2017-13020, CVE-2017-13021, CVE-2017-13022,
 CVE-2017-13023, CVE-2017-13024, CVE-2017-13025, CVE-2017-13026,
 CVE-2017-13027, CVE-2017-13028, CVE-2017-13029, CVE-2017-13030,
 CVE-2017-13031, CVE-2017-13032, CVE-2017-13033, CVE-2017-13034,
 CVE-2017-13035, CVE-2017-13036, CVE-2017-13037, CVE-2017-13038,
 CVE-2017-13039, CVE-2017-13040, CVE-2017-13041, CVE-2017-13042,
 CVE-2017-13043, CVE-2017-13044, CVE-2017-13045, CVE-2017-13046,
 CVE-2017-13047, CVE-2017-13048, CVE-2017-13049, CVE-2017-13050,
 CVE-2017-13051, CVE-2017-13052, CVE-2017-13053, CVE-2017-13054,
 CVE-2017-13055, CVE-2017-13687, CVE-2017-13688, CVE-2017-13689,
 CVE-2017-13690, CVE-2017-13725)");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"tcpdump", ver:"4.9.2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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
