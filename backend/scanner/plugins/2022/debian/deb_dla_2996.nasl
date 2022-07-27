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
  script_oid("1.3.6.1.4.1.25623.1.0.892996");
  script_version("2022-05-07T01:00:11+0000");
  script_cve_id("CVE-2017-9527", "CVE-2018-10191", "CVE-2018-11743", "CVE-2018-12249", "CVE-2018-14337", "CVE-2020-15866");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-09 10:04:03 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-07 01:00:11 +0000 (Sat, 07 May 2022)");
  script_name("Debian LTS: Security Advisory for mruby (DLA-2996-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2996-1");
  script_xref(name:"Advisory-ID", value:"DLA-2996-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mruby'
  package(s) announced via the DLA-2996-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in mruby, a lightweight
implementation of the Ruby language

CVE-2017-9527

heap-based use-after-free vulnerability allows attackers to cause
a denial of service or possibly have unspecified other impact via
a crafted .rb file

CVE-2018-10191

an integer overflow exists when handling OP_GETUPVAR in the
presence of deep scope nesting, resulting in a use-after-free. An
attacker that can cause Ruby code to be run can use this to
possibly execute arbitrary code

CVE-2018-11743

uninitialized pointer which allows attackers to cause a denial of
service or possibly have unspecified other impact.

CVE-2018-12249

There is a NULL pointer dereference in mrb_class_real because
'class BasicObject' is not properly supported in class.c.

CVE-2018-14337

a signed integer overflow, possibly leading to out-of-bounds
memory access because the mrb_str_resize function in string.c does
not check for a negative length

CVE-2020-15866

a heap-based buffer overflow in the mrb_yield_with_class function
in vm.c because of incorrect VM stack handling");

  script_tag(name:"affected", value:"'mruby' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.2.0+20161228+git30d5424a-1+deb9u1.

We recommend that you upgrade your mruby packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libmruby-dev", ver:"1.2.0+20161228+git30d5424a-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mruby", ver:"1.2.0+20161228+git30d5424a-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
