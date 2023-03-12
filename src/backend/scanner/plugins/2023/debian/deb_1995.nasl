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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.1995");
  script_cve_id("CVE-2009-0217", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302", "CVE-2010-0136");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1995)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1995");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1995");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1995 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenOffice.org office suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0136

It was discovered that macro security settings were insufficiently enforced for VBA macros.

CVE-2009-0217

It was discovered that the W3C XML Signature recommendation contains a protocol-level vulnerability related to HMAC output truncation. This also affects the integrated libxmlsec library.

CVE-2009-2949

Sebastian Apelt discovered that an integer overflow in the XPM import code may lead to the execution of arbitrary code.

CVE-2009-2950

Sebastian Apelt and Frank Reissner discovered that a buffer overflow in the GIF import code may lead to the execution of arbitrary code.

CVE-2009-3301/CVE-2009-3302 Nicolas Joly discovered multiple vulnerabilities in the parser for Word document files, which may lead to the execution of arbitrary code.

For the old stable distribution (etch), these problems have been fixed in version 2.0.4.dfsg.2-7etch9.

For the stable distribution (lenny), these problems have been fixed in version 1:2.4.1+dfsg-1+lenny6.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"broffice.org", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uno", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.4.dfsg.2-7etch9", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"broffice.org", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cli-uno-bridge", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmythes-dev", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-basetypes1.0-cil", ver:"1.0.10.0+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-cppuhelper1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-types1.1-cil", ver:"1.1.13.0+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-ure1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-openoffice.org", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base-core", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-common", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-core", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-emailmerge", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-binfilter", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-headless", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-eu", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-gl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mr-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ro", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uz", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-math", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-ogltrans", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-presentation-minimizer", ver:"1.0+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-report-builder-bin", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-report-builder", ver:"1:1.0.2+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-sdbc-postgresql", ver:"1:0.7.6+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-andromeda", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-tango", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uno", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1:2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure-dbg", ver:"1.4+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"1.4+OOo2.4.1+dfsg-1+lenny6", rls:"DEB5"))) {
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
