###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4a16e37c81_chromium_fc27.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for chromium FEDORA-2018-4a16e37c81
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
  script_oid("1.3.6.1.4.1.25623.1.0.875088");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-22 08:01:46 +0200 (Sat, 22 Sep 2018)");
  script_cve_id("CVE-2018-16087", "CVE-2018-16088", "CVE-2018-16086", "CVE-2018-16065",
                "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069",
                "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16072", "CVE-2018-16073",
                "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077",
                "CVE-2018-16078", "CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150",
                "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154",
                "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158",
                "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163",
                "CVE-2018-6149", "CVE-2018-16085", "CVE-2018-16084", "CVE-2018-16083",
                "CVE-2018-16082", "CVE-2018-16081", "CVE-2018-16080", "CVE-2018-16079",
                "CVE-2018-6179", "CVE-2018-6178", "CVE-2018-6177", "CVE-2018-6176",
                "CVE-2018-6175", "CVE-2018-6174", "CVE-2018-6173", "CVE-2018-6172",
                "CVE-2018-6171", "CVE-2018-6170", "CVE-2018-6169", "CVE-2018-6168",
                "CVE-2018-6167", "CVE-2018-6166", "CVE-2018-6165", "CVE-2018-6164",
                "CVE-2018-6160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2018-4a16e37c81");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"affected", value:"chromium on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FMMNOEV64HA4BUMOM47O2SBMMOHYKYTH");
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

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~69.0.3497.92~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
