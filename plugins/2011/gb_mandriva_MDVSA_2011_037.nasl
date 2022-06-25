###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for avahi MDVSA-2011:037 (avahi)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-02/msg00020.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831336");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2244", "CVE-2011-1002");
  script_name("Mandriva Update for avahi MDVSA-2011:037 (avahi)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1|2010\.0|2009\.0)");
  script_tag(name:"affected", value:"avahi on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in avahi:

  avahi-core/socket.c in avahi-daemon in Avahi before 0.6.29 allows
  remote attackers to cause a denial of service (infinite loop) via
  an empty (1) IPv4 or (2) IPv6 UDP packet to port 5353.  NOTE: this
  vulnerability exists because of an incorrect fix for CVE-2010-2244
  (CVE-2011-1002).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core5", rpm:"libavahi-core5~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core5", rpm:"lib64avahi-core5~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.23~1.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core6", rpm:"libavahi-core6~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core6", rpm:"lib64avahi-core6~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.25~5.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core6", rpm:"libavahi-core6~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core6", rpm:"lib64avahi-core6~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.25~3.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core5", rpm:"libavahi-core5~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core5", rpm:"lib64avahi-core5~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.23~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
