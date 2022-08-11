# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892872");
  script_version("2021-12-31T14:03:13+0000");
  script_cve_id("CVE-2019-6245");
  script_name("Debian LTS: Security Advisory for agg (DLA-2872-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"last_modification", value:"2021-12-31 14:03:13 +0000 (Fri, 31 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-31 02:00:10 +0000 (Fri, 31 Dec 2021)");

  script_tag(name:"cvssv2_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"cvssv2_base_score", value:"6.8");
  script_tag(name:"cvssv2_base_score_overall", value:"6.8");
  script_tag(name:"cvssv2_base_impact", value:"6.4");
  script_tag(name:"cvssv2_base_exploit", value:"8.6");
  script_tag(name:"cvssv2_em_access_vector", value:"Network");
  script_tag(name:"cvssv2_em_access_complex", value:"Medium");
  script_tag(name:"cvssv2_em_authentication", value:"None");
  script_tag(name:"cvssv2_impact_ci", value:"Partial");
  script_tag(name:"cvssv2_impact_ii", value:"Partial");
  script_tag(name:"cvssv2_impact_ai", value:"Partial");

  script_tag(name:"cvssv3_base_vector", value:"AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"cvssv3_base_score", value:"8.8");
  script_tag(name:"cvssv3_base_score_overall", value:"8.8");
  script_tag(name:"cvssv3_base_impact", value:"5.9");
  script_tag(name:"cvssv3_base_exploit", value:"2.8");
  script_tag(name:"cvssv3_em_attack_vector", value:"Network");
  script_tag(name:"cvssv3_em_attack_complex", value:"Low");
  script_tag(name:"cvssv3_em_priv_required", value:"None");
  script_tag(name:"cvssv3_em_user_interact", value:"Required");
  script_tag(name:"cvssv3_scope", value:"Unchanged");
  script_tag(name:"cvssv3_impact_ci", value:"High");
  script_tag(name:"cvssv3_impact_ii", value:"High");
  script_tag(name:"cvssv3_impact_ai", value:"High");

  script_tag(name:"pci_dss", value:"Fail");

  script_tag(name:"cpe", value:"cpe:2.3:a:antigrain:agg:2.4:*:*:*:*:*:*:*,
  cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*");

  script_tag(name:"url_ref", value:"https://lists.debian.org/debian-lts-announce/2021/12/msg00038.html,
  https://github.com/svgpp/svgpp/issues/70,
  https://bugs.debian.org/919322");

  script_tag(name:"cwe_id", value:"CWE-674");

  script_tag(name:"cve_date", value:"2019-01-12");
  script_tag(name:"patch_date", value:"2019-01-13");

  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/12/msg00038.html");
  script_xref(name:"URL", value:"https://bugs.debian.org/919322");
  script_xref(name:"URL", value:"https://github.com/svgpp/svgpp/issues/70");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'agg' package(s) announced via the DLA-2872-1 advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");
  script_tag(name:"insight", value:"Stack overflow due to infinite recursion was fixed in agg, the Anti-Grain Geometry graphical toolkit.");
  script_tag(name:"affected", value:"'agg' package(s) on Debian Linux.");
  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version 2.5+dfsg1-11+deb9u1. We recommend that you upgrade your agg packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libagg-dev", ver:"2.5+dfsg1-11+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
