###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for OpenOffice_org SUSE-SA:2010:017
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
tag_insight = "This update of OpenOffice_org includes fixes for the following
  vulnerabilities:

  - CVE-2009-0217: XML signature weakness
  - CVE-2009-2949: XPM Import Integer Overflow
  - CVE-2009-2950: GIF Import Heap Overflow
  - CVE-2009-3301: MS Word sprmTDefTable Memory Corruption
  - CVE-2009-3302: MS Word sprmTDefTable Memory Corruption
  - CVE-2010-0136: In the ooo-build variant of OpenOffice_org VBA Macro
  support does not honor Macro security settings.

  Please note that not all versions are affected by all bugs.

  On SUSE Linux Enterprise Desktop 10 SP2 and SP3 and SUSE Linux
  Enterprise Desktop 11 OpenOffice_org was updated to version 3.2.

  The changelog file of the RPM file will give you detailed information.

  Also released was the Novell Edition of OpenOffice.org for Windows,";

tag_impact = "remote code execution";
tag_affected = "OpenOffice_org on openSUSE 11.0, openSUSE 11.1, openSUSE 11.2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.312858");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0217", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302", "CVE-2010-0136");
  script_name("SuSE Update for OpenOffice_org SUSE-SA:2010:017");

  script_tag(name: "summary" , value: "Check for the Version of OpenOffice_org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-base", rpm:"OpenOffice_org-base~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-branding-upstream", rpm:"OpenOffice_org-branding-upstream~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-calc", rpm:"OpenOffice_org-calc~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-devel", rpm:"OpenOffice_org-devel~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-draw", rpm:"OpenOffice_org-draw~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-filters", rpm:"OpenOffice_org-filters~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-icon-themes-prebuilt", rpm:"OpenOffice_org-icon-themes-prebuilt~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-impress", rpm:"OpenOffice_org-impress~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mailmerge", rpm:"OpenOffice_org-mailmerge~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-math", rpm:"OpenOffice_org-math~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pyuno", rpm:"OpenOffice_org-pyuno~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk", rpm:"OpenOffice_org-sdk~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk-doc", rpm:"OpenOffice_org-sdk-doc~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-testtool", rpm:"OpenOffice_org-testtool~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer", rpm:"OpenOffice_org-writer~2.4.0.14~1.6", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org-base-drivers-postgresql", rpm:"OpenOffice_org-base-drivers-postgresql~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core", rpm:"OpenOffice_org-libs-core~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core-devel", rpm:"OpenOffice_org-libs-core-devel~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core-l10n-prebuilt", rpm:"OpenOffice_org-libs-core-l10n-prebuilt~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern", rpm:"OpenOffice_org-libs-extern~3.0.0.9~1.15.19", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern-devel", rpm:"OpenOffice_org-libs-extern-devel~3.0.0.9~1.15.19", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern-l10n-prebuilt", rpm:"OpenOffice_org-libs-extern-l10n-prebuilt~3.0.0.9~1.15.19", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui", rpm:"OpenOffice_org-libs-gui~3.0.0.9~1.12.22", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui-devel", rpm:"OpenOffice_org-libs-gui-devel~3.0.0.9~1.12.22", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui-l10n-prebuilt", rpm:"OpenOffice_org-libs-gui-l10n-prebuilt~3.0.0.9~1.12.22", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mailmerge", rpm:"OpenOffice_org-mailmerge~3.0.0.9~1.11.23", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-math", rpm:"OpenOffice_org-math~3.0.0.9~2.9.16", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer", rpm:"OpenOffice_org-writer~3.0.0.9~2.9.16", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer-devel", rpm:"OpenOffice_org-writer-devel~3.0.0.9~2.9.16", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer-l10n-prebuilt", rpm:"OpenOffice_org-writer-l10n-prebuilt~3.0.0.9~2.9.16", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org-base-drivers-postgresql", rpm:"OpenOffice_org-base-drivers-postgresql~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-components", rpm:"OpenOffice_org-components~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-components-devel", rpm:"OpenOffice_org-components-devel~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-components-l10n-prebuilt", rpm:"OpenOffice_org-components-l10n-prebuilt~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde4", rpm:"OpenOffice_org-kde4~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core", rpm:"OpenOffice_org-libs-core~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core-devel", rpm:"OpenOffice_org-libs-core-devel~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-core-l10n-prebuilt", rpm:"OpenOffice_org-libs-core-l10n-prebuilt~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern", rpm:"OpenOffice_org-libs-extern~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern-devel", rpm:"OpenOffice_org-libs-extern-devel~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-extern-l10n-prebuilt", rpm:"OpenOffice_org-libs-extern-l10n-prebuilt~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui", rpm:"OpenOffice_org-libs-gui~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui-devel", rpm:"OpenOffice_org-libs-gui-devel~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-libs-gui-l10n-prebuilt", rpm:"OpenOffice_org-libs-gui-l10n-prebuilt~3.1.1.4~1.1.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mailmerge", rpm:"OpenOffice_org-mailmerge~3.1.1.4~1.2.2", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-math", rpm:"OpenOffice_org-math~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-testtool", rpm:"OpenOffice_org-testtool~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer", rpm:"OpenOffice_org-writer~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer-devel", rpm:"OpenOffice_org-writer-devel~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer-l10n-prebuilt", rpm:"OpenOffice_org-writer-l10n-prebuilt~3.1.1.4~1.2.3", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
