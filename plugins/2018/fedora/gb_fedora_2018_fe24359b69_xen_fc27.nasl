###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_fe24359b69_xen_fc27.nasl 14223 2019-03-15 13:49:35Z cfischer $
#
# Fedora Update for xen FEDORA-2018-fe24359b69
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
  script_oid("1.3.6.1.4.1.25623.1.0.875287");
  script_version("$Revision: 14223 $");
  script_cve_id("CVE-2018-18883", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-15469",
                "CVE-2018-15468", "CVE-2018-15470", "CVE-2018-12891", "CVE-2018-12893",
                "CVE-2018-12892", "CVE-2018-3665", "CVE-2018-3639", "CVE-2018-8897",
                "CVE-2018-10982", "CVE-2018-10981", "CVE-2018-7540", "CVE-2018-7541",
                "CVE-2018-7542", "CVE-2017-15595", "CVE-2017-17566", "CVE-2017-17563",
                "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17044", "CVE-2017-17045",
                "CVE-2017-15592", "CVE-2017-15597", "CVE-2017-15590", "CVE-2017-15591",
                "CVE-2017-15589", "CVE-2017-15588", "CVE-2017-15593", "CVE-2017-15594");
  script_bugtraq_id(106054);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-04 12:40:47 +0530 (Tue, 04 Dec 2018)");
  script_name("Fedora Update for xen FEDORA-2018-fe24359b69");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XCNCVBHUTUKAEDCTEZO6MK4PF3AI6XTE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the FEDORA-2018-fe24359b69 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"xen on Fedora 27.");

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

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.3~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}