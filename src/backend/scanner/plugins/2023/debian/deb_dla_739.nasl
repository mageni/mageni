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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.739");
  script_cve_id("CVE-2016-10249", "CVE-2016-8654", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8887", "CVE-2016-9560");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:08:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-739)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-739");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-739");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jasper' package(s) announced via the DLA-739 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-8691

FPE on unknown address ... jpc_dec_process_siz ... jpc_dec.c

CVE-2016-8692

FPE on unknown address ... jpc_dec_process_siz ... jpc_dec.c

CVE-2016-8693

attempting double-free ... mem_close ... jas_stream.c

CVE-2016-8882

segfault / null pointer access in jpc_pi_destroy

CVE-2016-9560

stack-based buffer overflow in jpc_tsfb_getbands2 (jpc_tsfb.c)

CVE-2016-8887 part 1 + 2 NULL pointer dereference in jp2_colr_destroy (jp2_cod.c)

CVE-2016-8654

Heap-based buffer overflow in QMFB code in JPC codec

CVE-2016-8883

assert in jpc_dec_tiledecode()

TEMP-CVE heap-based buffer overflow in jpc_dec_tiledecode (jpc_dec.c)

For Debian 7 Wheezy, these problems have been fixed in version 1.900.1-13+deb7u5.

We recommend that you upgrade your jasper packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jasper' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-13+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-13+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-13+deb7u5", rls:"DEB7"))) {
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
