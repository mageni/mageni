###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openoffice.org MDVA-2011:000 (openoffice.org)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-01/msg00000.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831298");
  script_version("$Revision: 14188 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:14:02 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-11 16:07:49 +0100 (Tue, 11 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Mandriva Update for openoffice.org MDVA-2011:000 (openoffice.org)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2010\.1");
  script_tag(name:"affected", value:"openoffice.org on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"This is a bugfix and maintenance advisory that upgrades OpenOffice.org
  to the 3.2.1 version. Additionally a couple of Mandriva reported bugs
  has been fixed as described as follows:

  Openoffice.org status bar items got hidden whenever using
  openoffice.org-kde4 package integration.

  Viewing OpenOffice.org documents inside Firefox under 64bits 2010.1
  version was not possible.

  Additionally OpenOffice.org 3.2.1 requires saxon9 that is also provided
  with this advisory.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-common", rpm:"openoffice.org-common~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel-doc", rpm:"openoffice.org-devel-doc~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-filter-binfilter", rpm:"openoffice.org-filter-binfilter~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-gnome", rpm:"openoffice.org-gnome~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-af", rpm:"openoffice.org-help-af~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ar", rpm:"openoffice.org-help-ar~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bg", rpm:"openoffice.org-help-bg~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-br", rpm:"openoffice.org-help-br~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bs", rpm:"openoffice.org-help-bs~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ca", rpm:"openoffice.org-help-ca~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cs", rpm:"openoffice.org-help-cs~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cy", rpm:"openoffice.org-help-cy~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-da", rpm:"openoffice.org-help-da~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-de", rpm:"openoffice.org-help-de~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-el", rpm:"openoffice.org-help-el~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_GB", rpm:"openoffice.org-help-en_GB~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_US", rpm:"openoffice.org-help-en_US~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-es", rpm:"openoffice.org-help-es~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-et", rpm:"openoffice.org-help-et~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-eu", rpm:"openoffice.org-help-eu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fi", rpm:"openoffice.org-help-fi~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fr", rpm:"openoffice.org-help-fr~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-he", rpm:"openoffice.org-help-he~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hi", rpm:"openoffice.org-help-hi~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hu", rpm:"openoffice.org-help-hu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-it", rpm:"openoffice.org-help-it~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ja", rpm:"openoffice.org-help-ja~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ko", rpm:"openoffice.org-help-ko~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-mk", rpm:"openoffice.org-help-mk~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nb", rpm:"openoffice.org-help-nb~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nl", rpm:"openoffice.org-help-nl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nn", rpm:"openoffice.org-help-nn~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pl", rpm:"openoffice.org-help-pl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt", rpm:"openoffice.org-help-pt~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt_AO", rpm:"openoffice.org-help-pt_AO~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt_BR", rpm:"openoffice.org-help-pt_BR~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ru", rpm:"openoffice.org-help-ru~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sk", rpm:"openoffice.org-help-sk~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sl", rpm:"openoffice.org-help-sl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sv", rpm:"openoffice.org-help-sv~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ta", rpm:"openoffice.org-help-ta~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-tr", rpm:"openoffice.org-help-tr~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_CN", rpm:"openoffice.org-help-zh_CN~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_TW", rpm:"openoffice.org-help-zh_TW~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zu", rpm:"openoffice.org-help-zu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-java-common", rpm:"openoffice.org-java-common~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-kde4", rpm:"openoffice.org-kde4~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-af", rpm:"openoffice.org-l10n-af~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ar", rpm:"openoffice.org-l10n-ar~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bg", rpm:"openoffice.org-l10n-bg~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-br", rpm:"openoffice.org-l10n-br~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bs", rpm:"openoffice.org-l10n-bs~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ca", rpm:"openoffice.org-l10n-ca~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cs", rpm:"openoffice.org-l10n-cs~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cy", rpm:"openoffice.org-l10n-cy~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-da", rpm:"openoffice.org-l10n-da~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-de", rpm:"openoffice.org-l10n-de~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-el", rpm:"openoffice.org-l10n-el~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-en_GB", rpm:"openoffice.org-l10n-en_GB~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-es", rpm:"openoffice.org-l10n-es~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-et", rpm:"openoffice.org-l10n-et~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-eu", rpm:"openoffice.org-l10n-eu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fi", rpm:"openoffice.org-l10n-fi~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fr", rpm:"openoffice.org-l10n-fr~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-he", rpm:"openoffice.org-l10n-he~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hi", rpm:"openoffice.org-l10n-hi~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hu", rpm:"openoffice.org-l10n-hu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-it", rpm:"openoffice.org-l10n-it~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ja", rpm:"openoffice.org-l10n-ja~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ko", rpm:"openoffice.org-l10n-ko~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-mk", rpm:"openoffice.org-l10n-mk~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nb", rpm:"openoffice.org-l10n-nb~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nl", rpm:"openoffice.org-l10n-nl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nn", rpm:"openoffice.org-l10n-nn~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pl", rpm:"openoffice.org-l10n-pl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt", rpm:"openoffice.org-l10n-pt~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_AO", rpm:"openoffice.org-l10n-pt_AO~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_BR", rpm:"openoffice.org-l10n-pt_BR~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ru", rpm:"openoffice.org-l10n-ru~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sk", rpm:"openoffice.org-l10n-sk~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sl", rpm:"openoffice.org-l10n-sl~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sv", rpm:"openoffice.org-l10n-sv~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ta", rpm:"openoffice.org-l10n-ta~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-tr", rpm:"openoffice.org-l10n-tr~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_CN", rpm:"openoffice.org-l10n-zh_CN~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_TW", rpm:"openoffice.org-l10n-zh_TW~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zu", rpm:"openoffice.org-l10n-zu~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-mono", rpm:"openoffice.org-mono~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-openclipart", rpm:"openoffice.org-openclipart~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pdfimport", rpm:"openoffice.org-pdfimport~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presentation-minimizer", rpm:"openoffice.org-presentation-minimizer~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presenter-screen", rpm:"openoffice.org-presenter-screen~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-crystal", rpm:"openoffice.org-style-crystal~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-galaxy", rpm:"openoffice.org-style-galaxy~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-hicontrast", rpm:"openoffice.org-style-hicontrast~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-industrial", rpm:"openoffice.org-style-industrial~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-oxygen", rpm:"openoffice.org-style-oxygen~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-tango", rpm:"openoffice.org-style-tango~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtool", rpm:"openoffice.org-testtool~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-wiki-publisher", rpm:"openoffice.org-wiki-publisher~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.2.1~0.2mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"saxon9", rpm:"saxon9~9.2.0.3~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"saxon9-demo", rpm:"saxon9-demo~9.2.0.3~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"saxon9-javadoc", rpm:"saxon9-javadoc~9.2.0.3~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"saxon9-manual", rpm:"saxon9-manual~9.2.0.3~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"saxon9-scripts", rpm:"saxon9-scripts~9.2.0.3~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
