###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2465_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for python-Jinja2 openSUSE-SU-2016:2465-1 (python-Jinja2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851405");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-07 05:44:06 +0200 (Fri, 07 Oct 2016)");
  script_cve_id("CVE-2014-0012");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for python-Jinja2 openSUSE-SU-2016:2465-1 (python-Jinja2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Jinja2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for python-Jinja2 fixes the following issues:

  Update to version 2.8:

  - Added `target` parameter to urlize function.

  - Added support for `followsymlinks` to the file system loader.

  - The truncate filter now counts the length.

  - Added equalto filter that helps with select filters.

  - Changed cache keys to use absolute file names if available instead of
  load names.

  - Fixed loop length calculation for some iterators.

  - Changed how Jinja2 enforces strings to be native strings in Python 2 to
  work when people break their default encoding.

  - Added :func:`make_logging_undefined` which returns an undefined
  object that logs failures into a logger.

  - If unmarshalling of cached data fails the template will be reloaded now.

  - Implemented a block ``set`` tag.

  - Default cache size was incrased to 400 from a low 50.

  - Fixed ``is number`` test to accept long integers in all Python versions.

  - Changed ``is number`` to accept Decimal as a number.

  - Added a check for default arguments followed by non-default arguments.
  This change makes ``{% macro m(x, y=1, z) %}...{% endmacro %}`` a syntax
  error. The previous behavior for this code was broken anyway (resulting
  in the default value being applied to `y`).

  - Add ability to use custom subclasses of
  ``jinja2.compiler.CodeGenerator`` and ``jinja2.runtime.Context`` by
  adding two new attributes to the environment (`code_generator_class` and
  `context_class`) (pull request ``#404``).

  - added support for context/environment/evalctx decorator functions on the
  finalize callback of the environment.

  - escape query strings for urlencode properly.  Previously slashes were
  not escaped in that place.

  - Add 'base' parameter to 'int' filter.

  - Update to 2.7.3 (boo#858239, CVE-2014-0012)");
  script_tag(name:"affected", value:"python-Jinja2 on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"python-Jinja2", rpm:"python-Jinja2~2.8~3.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-Jinja2-emacs", rpm:"python-Jinja2-emacs~2.8~3.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-Jinja2-vim", rpm:"python-Jinja2-vim~2.8~3.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
