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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2105");
  script_cve_id("CVE-2010-1797", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808", "CVE-2010-3053");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2105");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2105");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-2105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FreeType font library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1797

Multiple stack-based buffer overflows in the cff_decoder_parse_charstrings function in the CFF Type2 CharStrings interpreter in cff/cffgload.c in FreeType allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted CFF opcodes in embedded fonts in a PDF document, as demonstrated by JailbreakMe.

CVE-2010-2541

Buffer overflow in ftmulti.c in the ftmulti demo program in FreeType allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted font file.

CVE-2010-2805

The FT_Stream_EnterFrame function in base/ftstream.c in FreeType does not properly validate certain position values, which allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted font file

CVE-2010-2806

Array index error in the t42_parse_sfnts function in type42/t42parse.c in FreeType allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via negative size values for certain strings in FontType42 font files, leading to a heap-based buffer overflow.

CVE-2010-2807

FreeType uses incorrect integer data types during bounds checking, which allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted font file.

CVE-2010-2808

Buffer overflow in the Mac_Read_POST_Resource function in base/ftobjs.c in FreeType allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via a crafted Adobe Type 1 Mac Font File (aka LWFN) font.

CVE-2010-3053

bdf/bdflib.c in FreeType allows remote attackers to cause a denial of service (application crash) via a crafted BDF font file, related to an attempted modification of a value in a static string.

For the stable distribution (lenny), these problems have been fixed in version 2.3.7-2+lenny3

For the unstable distribution (sid) and the testing distribution (squeeze), these problems have been fixed in version 2.4.2-1

We recommend that you upgrade your freetype package.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.3.7-2+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.3.7-2+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.3.7-2+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.7-2+lenny3", rls:"DEB5"))) {
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
