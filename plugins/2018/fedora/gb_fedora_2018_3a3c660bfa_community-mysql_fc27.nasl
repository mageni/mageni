###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_3a3c660bfa_community-mysql_fc27.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for community-mysql FEDORA-2018-3a3c660bfa
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
  script_oid("1.3.6.1.4.1.25623.1.0.875053");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-12 07:18:11 +0200 (Wed, 12 Sep 2018)");
  script_cve_id("CVE-2018-2767", "CVE-2018-3056", "CVE-2018-3058", "CVE-2018-3060",
                "CVE-2018-3061", "CVE-2018-3062", "CVE-2018-3064", "CVE-2018-3065",
                "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3071", "CVE-2018-3077",
                "CVE-2018-3081", "CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2759",
                "CVE-2018-2761", "CVE-2018-2762", "CVE-2018-2766", "CVE-2018-2769",
                "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2775", "CVE-2018-2776",
                "CVE-2018-2777", "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2780",
                "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2786",
                "CVE-2018-2787", "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2813",
                "CVE-2018-2816", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819",
                "CVE-2018-2839", "CVE-2018-2846", "CVE-2017-10155", "CVE-2017-10227",
                "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10279", "CVE-2017-10283",
                "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10314", "CVE-2017-10378",
                "CVE-2017-10379", "CVE-2017-10384");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for community-mysql FEDORA-2018-3a3c660bfa");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"affected", value:"community-mysql on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CMFLV7EQQMQLID4QLMAD66RUMXI776RR");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

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

  if ((res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~5.7.23~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
