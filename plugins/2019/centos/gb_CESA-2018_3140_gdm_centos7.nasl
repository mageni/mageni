###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_3140_gdm_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for gdm CESA-2018:3140 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883002");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2017-18267", "CVE-2018-10733", "CVE-2018-10767", "CVE-2018-10768", "CVE-2018-12910", "CVE-2018-13988");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-02 04:04:31 +0100 (Sat, 02 Feb 2019)");
  script_name("CentOS Update for gdm CESA-2018:3140 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-February/023179.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm'
  package(s) announced via the CESA-2018:3140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME is the default desktop environment of Red Hat Enterprise Linux.

Security Fix(es):

  * libsoup: Crash in soup_cookie_jar.c:get_cookies() on empty hostnames
(CVE-2018-12910)

  * poppler: Infinite recursion in fofi/FoFiType1C.cc:FoFiType1C::cvtGlyph()
function allows denial of service (CVE-2017-18267)

  * libgxps: heap based buffer over read in ft_font_face_hash function of
gxps-fonts.c (CVE-2018-10733)

  * libgxps: Stack-based buffer overflow in calling glib in
gxps_images_guess_content_type of gcontenttype.c (CVE-2018-10767)

  * poppler: NULL pointer dereference in Annot.h:AnnotPath::getCoordsLength()
allows for denial of service via crafted PDF (CVE-2018-10768)

  * poppler: out of bounds read in pdfunite (CVE-2018-13988)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank chenyuan (NESA Lab) for reporting
CVE-2018-10733 and CVE-2018-10767 and Hosein Askari for reporting
CVE-2018-13988.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section.");

  script_tag(name:"affected", value:"gdm on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~3.28.2~11.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-devel", rpm:"gdm-devel~3.28.2~11.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-pam-extensions-devel", rpm:"gdm-pam-extensions-devel~3.28.2~11.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
