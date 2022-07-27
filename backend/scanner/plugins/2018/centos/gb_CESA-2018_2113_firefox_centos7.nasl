###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2113_firefox_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for firefox CESA-2018:2113 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882918");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-12 05:56:51 +0200 (Thu, 12 Jul 2018)");
  script_cve_id("CVE-2017-7762", "CVE-2018-5156", "CVE-2018-5188", "CVE-2018-6126",
                "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363",
                "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2018:2113 centos7");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
  compliance, performance, and portability.

This update upgrades Firefox to version 60.1.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 61, Firefox ESR 60.1, and
Firefox ESR 52.9 (CVE-2018-5188)

  * Mozilla: Buffer overflow using computed size of canvas element
(CVE-2018-12359)

  * Mozilla: Use-after-free using focus() (CVE-2018-12360)

  * Mozilla: Media recorder segmentation fault when track type is changed
during capture (CVE-2018-5156)

  * Skia: Heap buffer overflow rasterizing paths in SVG (CVE-2018-6126)

  * Mozilla: Integer overflow in SSSE3 scaler (CVE-2018-12362)

  * Mozilla: Use-after-free when appending DOM nodes (CVE-2018-12363)

  * Mozilla: CSRF attacks through 307 redirects and NPAPI plugins
(CVE-2018-12364)

  * Mozilla: address bar username and password spoofing in reader mode
(CVE-2017-7762)

  * Mozilla: Compromised IPC child process can list local filenames
(CVE-2018-12365)

  * Mozilla: Invalid data handling during QCMS transformations
(CVE-2018-12366)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Alex Gaynor, Christoph Diehl, Christian Holler, Jason
Kratzer, David Major, Jon Coppeard, Nicolas B. Pierron, Marcia Knous,
Ronald Crane, Nils, F. Alonso (revskills), David Black, and OSS-Fuzz as the
original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-July/022960.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.1.0~4.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
