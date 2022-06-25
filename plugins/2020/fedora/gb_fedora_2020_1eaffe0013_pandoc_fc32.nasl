# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.878430");
  script_version("2020-10-08T07:56:44+0000");
  script_cve_id("CVE-2020-5238");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-10-08 09:52:37 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-07 03:09:22 +0000 (Wed, 07 Oct 2020)");
  script_name("Fedora: Security Advisory for pandoc (FEDORA-2020-1eaffe0013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-1eaffe0013");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZGJH2A4VAV54X6NSCNNGSEIGIIY5N2VR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pandoc'
  package(s) announced via the FEDORA-2020-1eaffe0013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pandoc is a Haskell library for converting from one markup format to another,
and a command-line tool that uses this library. It can read several dialects of
Markdown and (subsets of) HTML, reStructuredText, LaTeX, DocBook, JATS,
MediaWiki markup, DokuWiki markup, TWiki markup, TikiWiki markup, Creole 1.0,
Haddock markup, OPML, Emacs Org-Mode, Emacs Muse, txt2tags, ipynb (Jupyter
notebooks), Vimwiki, Word Docx, ODT, EPUB, FictionBook2, roff man, and Textile,
and it can write Markdown, reStructuredText, XHTML, HTML 5, LaTeX, ConTeXt,
DocBook, JATS, OPML, TEI, OpenDocument, ODT, Word docx, PowerPoint pptx, RTF,
MediaWiki, DokuWiki, XWiki, ZimWiki, Textile, Jira, roff man, roff ms, plain
text, Emacs Org-Mode, AsciiDoc, Haddock markup, EPUB (v2 and v3), ipynb,
FictionBook2, InDesign ICML, Muse, LaTeX beamer slides, and several kinds of
HTML/JavaScript slide shows (S5, Slidy, Slideous, DZSlides, reveal.js).

In contrast to most existing tools for converting Markdown to HTML, pandoc has
a modular design: it consists of a set of readers, which parse text in a given
format and produce a native representation of the document, and a set of
writers, which convert this native representation into a target format.
Thus, adding an input or output format requires only adding a reader or writer.

For pdf output please also install pandoc-pdf or weasyprint.");

  script_tag(name:"affected", value:"'pandoc' package(s) on Fedora 32.");

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
report = "";

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"pandoc", rpm:"pandoc~2.7.3~4.fc32", rls:"FC32"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);