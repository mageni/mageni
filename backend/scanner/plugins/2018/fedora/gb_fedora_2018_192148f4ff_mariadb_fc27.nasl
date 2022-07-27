###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_192148f4ff_mariadb_fc27.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for mariadb FEDORA-2018-192148f4ff
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.875288");
  script_version("$Revision: 14223 $");
  script_cve_id("CVE-2018-3282", "CVE-2016-9843", "CVE-2018-3174", "CVE-2018-3143",
                  "CVE-2018-3156", "CVE-2018-3251", "CVE-2018-3185", "CVE-2018-3277", "CVE-2018-3162",
                  "CVE-2018-3173", "CVE-2018-3200", "CVE-2018-3284", "CVE-2018-3060", "CVE-2018-3064",
                  "CVE-2018-3063", "CVE-2018-3058", "CVE-2018-3066", "CVE-2018-2767", "CVE-2018-3081",
                  "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2771", "CVE-2018-2781",
                  "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817",
                  "CVE-2018-2819", "CVE-2018-2786", "CVE-2018-2759", "CVE-2018-2777",
                  "CVE-2018-2810");
  script_bugtraq_id(106054);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-04 12:40:37 +0530 (Tue, 04 Dec 2018)");
  script_name("Fedora Update for mariadb FEDORA-2018-192148f4ff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VA7N3SMG43EHYFMZCVRJ6KVKUKK2VFUJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the FEDORA-2018-192148f4ff advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"mariadb on Fedora 27.");

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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.2.19~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}