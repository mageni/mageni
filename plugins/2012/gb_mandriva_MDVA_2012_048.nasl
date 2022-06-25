###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for firefox MDVA-2012:048 (firefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVA-2012:048");
  script_oid("1.3.6.1.4.1.25623.1.0.831688");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:33:07 +0530 (Fri, 22 Jun 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandriva Update for firefox MDVA-2012:048 (firefox)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"firefox on Mandriva Linux 2011.0");
  script_tag(name:"insight", value:"This is a maintenance and bugfix release that upgrades firefox to
  the latest version which resolves various upstream bugs.");
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

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hy", rpm:"firefox-hy~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lg", rpm:"firefox-lg~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nso", rpm:"firefox-nso~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ta_LK", rpm:"firefox-ta_LK~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zu", rpm:"firefox-zu~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.1.5~0.3~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.1.5~0.3~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxulrunner13.0.1", rpm:"libxulrunner13.0.1~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxulrunner-devel", rpm:"libxulrunner-devel~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~13.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~13.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xulrunner13.0.1", rpm:"lib64xulrunner13.0.1~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xulrunner-devel", rpm:"lib64xulrunner-devel~13.0.1~0.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
