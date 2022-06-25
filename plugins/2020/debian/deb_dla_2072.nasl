# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892072");
  script_version("2020-01-21T04:01:07+0000");
  script_cve_id("CVE-2018-21015", "CVE-2018-21016", "CVE-2019-13618", "CVE-2019-20161", "CVE-2019-20162", "CVE-2019-20163", "CVE-2019-20165", "CVE-2019-20170", "CVE-2019-20171", "CVE-2019-20208");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-21 04:01:07 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-21 04:01:07 +0000 (Tue, 21 Jan 2020)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 2072-1] gpac security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2072-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/940882");
  script_xref(name:"URL", value:"https://bugs.debian.org/932242");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpac'
  package(s) announced via the DSA-2072-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in gpac, a multimedia framework featuring
the MP4Box muxer.

CVE-2018-21015

AVC_DuplicateConfig() at isomedia/avc_ext.c allows remote
attackers to cause a denial of service (NULL pointer dereference
and application crash) via a crafted file.

CVE-2018-21016

audio_sample_entry_AddBox() at isomedia/box_code_base.c allows
remote attackers to cause a denial of service (heap-based buffer
over-read and application crash) via a crafted file.

CVE-2019-13618

isomedia/isom_read.c in libgpac.a has a heap-based buffer
over-read, as demonstrated by a crash in gf_m2ts_sync in
media_tools/mpegts.c.

CVE-2019-20161

heap-based buffer overflow in the function
ReadGF_IPMPX_WatermarkingInit() in odf/ipmpx_code.c.

CVE-2019-20162

heap-based buffer overflow in the function gf_isom_box_parse_ex()
in isomedia/box_funcs.c.

CVE-2019-20163

NULL pointer dereference in the function gf_odf_avc_cfg_write_bs()
in odf/descriptors.c.

CVE-2019-20165

NULL pointer dereference in the function ilst_item_Read() in
isomedia/box_code_apple.c.

CVE-2019-20170

invalid pointer dereference in the function GF_IPMPX_AUTH_Delete()
in odf/ipmpx_code.c.

CVE-2019-20171

memory leaks in metx_New in isomedia/box_code_base.c and abst_Read
in isomedia/box_code_adobe.c.

CVE-2019-20208

dimC_Read in isomedia/box_code_3gpp.c in GPAC 0.8.0 has a
stack-based buffer overflow.");

  script_tag(name:"affected", value:"'gpac' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.5.0+svn5324~dfsg1-1+deb8u5.

We recommend that you upgrade your gpac packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gpac", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpac-dbg", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpac-modules-base", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgpac-dbg", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgpac-dev", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgpac3", ver:"0.5.0+svn5324~dfsg1-1+deb8u5", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);