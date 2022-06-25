###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zabbix FEDORA-2010-0266
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "ZABBIX is software that monitors numerous parameters of a network and
  the health and integrity of servers. ZABBIX uses a flexible
  notification mechanism that allows users to configure e-mail based
  alerts for virtually any event.  This allows a fast reaction to server
  problems. ZABBIX offers excellent reporting and data visualisation
  features based on the stored data. This makes ZABBIX ideal for
  capacity planning.

  ZABBIX supports both polling and trapping. All ZABBIX reports and
  statistics, as well as configuration parameters are accessed through a
  web-based front end. A web-based front end ensures that the status of
  your network and the health of your servers can be assessed from any
  location. Properly configured, ZABBIX can play an important role in
  monitoring IT infrastructure. This is equally true for small
  organisations with a few servers and for large companies with a
  multitude of servers.";

tag_affected = "zabbix on Fedora 12";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-January/034413.html");
  script_oid("1.3.6.1.4.1.25623.1.0.312834");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:38:02 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-0266");
  script_cve_id("CVE-2009-4499", "CVE-2009-4501");
  script_name("Fedora Update for zabbix FEDORA-2010-0266");

  script_tag(name: "summary" , value: "Check for the Version of zabbix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~1.6.8~1.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
